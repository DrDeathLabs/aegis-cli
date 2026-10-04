import re

from aegis.providers.base import ProviderAdapter


class NessusAdapter(ProviderAdapter):
    name = "nessus"
    supported_variants = ("nessus_xml_report", "nessus_csv_export", "plugin_record")
    contract_version = "nessus-file-format-2026"
    aliases = {
        "source_record_id": ("source_finding_id", "sourceFindingId", "occurrence_id", "detection_id", "finding_id", "findingId", "id"),
        "title": ("pluginName", "plugin_name", "name", "title"),
        "description": ("description", "synopsis", "plugin_output"),
        "severity": ("severity", "risk_factor", "riskfactor"),
        "cvss_score": ("cvss3_base_score", "cvss3BaseScore", "cvss_base_score", "cvss"),
        "cvss_vector": ("cvss3_vector", "cvss3Vector", "cvss_vector"),
        "hostname": ("host", "hostname", "host_name"),
        "ip": ("host-ip", "ip", "ip_address"),
        "port": ("port", "port_number"),
        "protocol": ("protocol", "transport"),
        "solution": ("solution", "remediation", "recommendation"),
        "exploit_available": ("exploit_available", "exploitability", "exploit"),
    }
    native_fields = ("cvss_score", "cvss_vector", "exploit_available")

    @staticmethod
    def _local(tag):
        return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""

    @classmethod
    def _host_context(cls, host, host_index):
        """Extract ReportHost context with stable source pointers."""
        values = {}
        paths = {}
        hostname = host.attrib.get("name")
        if hostname:
            values["hostname"] = hostname
            paths["hostname"] = f"/xml/reporthost/{host_index}/@name"
        host_properties = next((child for child in host if cls._local(child.tag) == "hostproperties"), None)
        if host_properties is not None:
            aliases = {
                "hostip": "ip", "ip": "ip", "ipaddress": "ip",
                "assetcriticality": "asset_criticality",
                "assetpriority": "asset_criticality",
                "businesscriticality": "business_criticality",
                "businessimpact": "business_criticality",
                "internetexposed": "internet_exposed",
                "exposedtointernet": "internet_exposed",
                "networkzone": "network_zone", "networksegment": "network_zone",
                "zone": "network_zone", "segment": "network_zone",
                "compensatingcontrol": "compensating_controls",
                "compensatingcontrols": "compensating_controls",
                "control": "compensating_controls",
            }
            for tag_index, tag in enumerate(host_properties):
                if cls._local(tag.tag) != "tag":
                    continue
                key = re.sub(r"[^a-z0-9]", "", str(tag.attrib.get("name") or "").lower())
                field = aliases.get(key)
                text = (tag.text or "").strip()
                if not field or not text:
                    continue
                if field in values:
                    prior = values[field] if isinstance(values[field], list) else [values[field]]
                    values[field] = prior + [text]
                else:
                    values[field] = text
                paths.setdefault(field, f"/xml/reporthost/{host_index}/HostProperties/tag/{tag_index}")
        return {"values": values, "paths": paths,
                "source_pointer": f"/xml/reporthost/{host_index}/HostProperties"}

    def map_record(self, record):
        host_context = record.get("_aegis_host_context")
        source_record = {key: value for key, value in record.items() if key != "_aegis_host_context"}
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(source_record)
        plugin = source_record.get("pluginID", source_record.get("plugin_id", source_record.get("@pluginID")))
        if plugin not in (None, ""):
            values["vulnerability_identifier"], paths["vulnerability_identifier"] = plugin, "pluginID" if "pluginID" in source_record else "plugin_id" if "plugin_id" in source_record else "@pluginID"
            provider_metadata["plugin_id"] = plugin
        plugin_name = source_record.get("pluginName", source_record.get("plugin_name", source_record.get("@pluginName")))
        if plugin_name not in (None, ""):
            values["title"], paths["title"] = plugin_name, "pluginName" if "pluginName" in source_record else "@pluginName"
        if host_context:
            context_values = host_context.get("values") or {}
            context_paths = host_context.get("paths") or {}
            for field, value in context_values.items():
                if values.get(field) in (None, "", [], {}):
                    values[field] = value
                    paths[field] = context_paths.get(field, host_context.get("source_pointer", ""))
            provider_metadata["reporthost_context"] = host_context
        return values, paths, warnings, unmapped, confidence, provider_metadata

    def output_record(self, record):
        return {key: value for key, value in record.items() if key != "_aegis_host_context"}

    def records(self, path, *, selectors=None):
        from aegis.providers.base import iter_csv_records, iter_json_records, iter_xml_records, _xml_dict, parse_xml_root
        if path.suffix.lower() in {".nessus", ".xml"}:
            # Nessus report items are the vulnerability records. Their host is
            # retained as an explicit field when the XML tree supplies it.
            root = parse_xml_root(path)
            parents = {id(child): parent for parent in root.iter() for child in parent}
            host_indexes = {id(host): index for index, host in enumerate(
                element for element in root.iter() if self._local(element.tag) == "reporthost")}
            found = 0
            for element in root.iter():
                local = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""
                if local not in {"reportitem", "vuln", "vulnerability"}:
                    continue
                record_value = _xml_dict(element)
                record = record_value if isinstance(record_value, dict) else ({"#text": record_value} if record_value is not None else {})
                parent = parents.get(id(element))
                containing_host = None
                while parent is not None:
                    parent_local = parent.tag.rsplit("}", 1)[-1].lower() if isinstance(parent.tag, str) else ""
                    if parent_local == "reporthost":
                        containing_host = parent
                        host = parent.attrib.get("name")
                        if host and not record.get("host"):
                            record["host"] = host
                        break
                    parent = parents.get(id(parent))
                record["_xml_tag"] = local
                if containing_host is not None:
                    record["_aegis_host_context"] = self._host_context(
                        containing_host, host_indexes[id(containing_host)])
                found += 1
                yield record, f"/xml/{local}/{found - 1}"
            if found == 0:
                yield from iter_xml_records(path, tags=())
        elif path.suffix.lower() in {".csv", ".tsv"}:
            yield from iter_csv_records(path)
        else:
            yield from iter_json_records(path, selectors=selectors)
