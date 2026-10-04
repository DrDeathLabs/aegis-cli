"""Bounded analysis stop conditions adapted from Trident convergence.py."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConvergenceDecision:
    stop: bool
    reason: str


def convergence(*, iteration: int, max_iterations: int, unresolved: int, budget_exhausted: bool) -> ConvergenceDecision:
    if iteration >= max_iterations:
        return ConvergenceDecision(True, "max_iterations")
    if budget_exhausted:
        return ConvergenceDecision(True, "analysis_budget_exhausted")
    if unresolved == 0:
        return ConvergenceDecision(True, "no_unresolved_analysis")
    return ConvergenceDecision(False, "unresolved_analysis_remains")
