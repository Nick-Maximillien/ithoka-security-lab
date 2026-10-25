"""Inspect configured proxy variable names without retaining their values."""

from __future__ import annotations

import os

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation, utc_timestamp

_PROXY_NAMES = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}


def inspect_proxy_environment(environ: dict[str, str] | None = None) -> OSObservation:
    variables = os.environ if environ is None else environ
    names = sorted(
        key for key in variables
        if key.lower() in _PROXY_NAMES
    )
    return OSObservation(
        "linux",
        "proxies",
        "inspect",
        "current process environment",
        "process environment",
        utc_timestamp(),
        EnforcementStatus.PASS,
        values={"configured_variable_names": names, "values_redacted": True},
        coverage_limitations=(
            "absence of proxy variables does not prove egress blocking or absence of proxy configuration elsewhere",
        ),
    )
