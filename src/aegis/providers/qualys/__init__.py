from aegis.providers.base import ProviderAdapter, _xml_dict, parse_xml_root, iter_csv_records, iter_json_records


class QualysAdapter(ProviderAdapter):
    name = "qualys"
    supported_variants = ("host_list_detection_xml", "host_detection_api", "host_detection_csv")
    contract_version = "qualys-host-detection-2026"
    severity_scale = "qualys_1_5"
    aliases = {
        "source_record_id": ("source_finding_id", "SOURCE_FINDING_ID", "occurrence_id", "detection_id", "finding_id", "findingId", "id"),
        "title": ("TITLE", "title", "name"),
        "description": ("DIAGNOSIS", "diagnosis", "description", "CONSEQUENCE"),
        "severity": ("SEVERITY", "severity"),
        "vendor_risk_score": ("QDS", "qds", "riskScore", "risk_score"),
        "asset_id": ("ASSET_ID", "asset_id", "HOST_ID", "host_id"),
        "hostname": ("HOSTNAME", "hostname", "DNS", "dns"),
        "ip": ("IP", "ip", "IP_ADDRESS", "ip_address"),
        "solution": ("SOLUTION", "solution", "remediation"),
        "cve": ("CVE_ID", "CVE_LIST", "cve", "cve_id"),
        "vulnerability_identifier": ("UNIQUE_VULN_ID", "unique_vuln_id", "QID", "qid", "vuln_id"),
        "cvss_score": ("CVSS3_BASE", "CVSS3_BASE_SCORE", "cvss3_base", "cvss3_base_score", "cvss_score"),
    }
    native_fields = ("vendor_risk_score", "severity")

    def records(self, path, *, selectors=None):
        if path.suffix.lower() == ".xml":
            root = parse_xml_root(path)
            hosts = [element for element in root.iter() if str(element.tag).rsplit("}", 1)[-1].lower() == "host"]
            found = 0
            for host_index, host in enumerate(hosts):
                host_values = _xml_dict(host)
                host_values = host_values if isinstance(host_values, dict) else {}
                host_values = {str(key).lower(): value for key, value in host_values.items()}
                detections = [element for element in host.iter() if str(element.tag).rsplit("}", 1)[-1].lower() == "detection"]
                for detection_index, detection in enumerate(detections):
                    value = _xml_dict(detection)
                    record = value if isinstance(value, dict) else {"#text": value}
                    def child_text(names):
                        for name in names:
                            if host_values.get(name) not in (None, ""):
                                return host_values[name]
                        return None
                    record["asset_id"] = child_text(("id", "host_id"))
                    record["ip"] = child_text(("ip", "ip_address"))
                    record["hostname"] = child_text(("dns", "hostname", "fqdn"))
                    record["_aegis_qualys_host_context"] = {"host_index": host_index, "detection_index": detection_index,
                        "source_pointer": f"/xml/host/{host_index}"}
                    found += 1
                    yield record, f"/xml/host/{host_index}/detection/{detection_index}"
            if found == 0:
                raise ValueError("Qualys XML contains no HOST/DETECTION records")
        elif path.suffix.lower() in {".csv", ".tsv"}:
            yield from iter_csv_records(path)
        else:
            yield from iter_json_records(path, selectors=selectors)

    def map_record(self, record):
        values, paths, warnings, unmapped, confidence, provider_metadata = super().map_record(record)
        if record.get("UNIQUE_VULN_ID") not in (None, "") or record.get("QID") not in (None, ""):
            value = record.get("UNIQUE_VULN_ID") or record.get("QID")
            values["vulnerability_identifier"] = value
            paths["vulnerability_identifier"] = "UNIQUE_VULN_ID" if record.get("UNIQUE_VULN_ID") not in (None, "") else "QID"
            provider_metadata["unique_vuln_id"] = value
        if record.get("QID") not in (None, ""):
            provider_metadata["qid"] = record["QID"]
        if record.get("_aegis_qualys_host_context"):
            provider_metadata["host_context"] = record["_aegis_qualys_host_context"]
        unmapped = [field for field in unmapped if field not in set(paths.values())]
        return values, paths, warnings, unmapped, confidence, provider_metadata

    def output_record(self, record):
        return {key: value for key, value in record.items() if key != "_aegis_qualys_host_context"}
