"""Backend policy validation for researcher-supplied apparatus."""

from __future__ import annotations

import json
import re
from typing import Any

from .foundation import LabError, _memory_limit_mib, require_integer


def validate_compose_document(document: Any, definition: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on Compose features that can escape the disposable lab."""
    if not isinstance(document, dict):
        raise LabError("Compose definition must be a mapping")

    allowed_top = {"services", "networks", "version", "name"}
    unknown_top = set(document) - allowed_top
    if unknown_top:
        raise LabError(f"Compose top-level keys are not permitted: {', '.join(sorted(unknown_top))}")

    services = document.get("services")
    networks = document.get("networks")
    if not isinstance(services, dict) or not services:
        raise LabError("Compose definition must declare services")
    if not isinstance(networks, dict) or not networks:
        raise LabError("Compose definition must declare networks")

    apparatus = definition.get("apparatus", {})
    network = apparatus.get("network", {}) if isinstance(apparatus, dict) else {}
    logical = network.get("logical_name", "lab") if isinstance(network, dict) else "lab"
    declared = networks.get(logical)
    if not isinstance(declared, dict):
        raise LabError(f"Compose network {logical} must be a mapping")
    if declared.get("internal") is not True or declared.get("external") is True:
        raise LabError(f"Compose network {logical} must be internal and non-external")
    if declared.get("driver", "bridge") != "bridge":
        raise LabError(f"Compose network {logical} must use the bridge driver")
    allowed_network_keys = {"internal", "enable_ipv6", "labels", "driver"}
    unknown_network_keys = set(declared) - allowed_network_keys
    if unknown_network_keys:
        raise LabError(
            f"Compose network {logical} has unsupported options: "
            f"{', '.join(sorted(unknown_network_keys))}"
        )
    if set(networks) != {logical}:
        raise LabError("Compose must declare only the investigation internal network")
    if declared.get("name") or declared.get("external") or declared.get("attachable") is True:
        raise LabError(f"Compose network {logical}: custom/external network control is forbidden")
    policy = definition.get("network_policy", {})
    ipv6_policy = policy.get("boundaries", {}).get("ipv6", {}) if isinstance(policy, dict) else {}
    if declared.get("enable_ipv6") is True and ipv6_policy.get("mode", "deny") == "deny":
        raise LabError(f"Compose network {logical}: enable_ipv6 conflicts with the selected deny policy")

    # Compose has many alternate host-access and privilege paths. Reject them
    # explicitly rather than relying only on ports/volumes/network_mode.
    forbidden = {
        "build", "volumes", "volumes_from", "ports", "network_mode", "privileged",
        "cap_add", "devices", "device_cgroup_rules", "pid", "ipc", "uts", "cgroup",
        "cgroup_parent", "userns_mode", "runtime", "sysctls", "extra_hosts",
        "host_ipc", "host_pid", "secrets", "configs",
        "env_file", "credential_spec", "external_links", "links", "mac_address",
        "use_api_socket", "provider", "develop", "extends", "post_start", "pre_stop", "container_name", "group_add",
    }
    for name, service in services.items():
        if not isinstance(service, dict):
            raise LabError(f"Compose service {name} must be a mapping")
        present = forbidden.intersection(service)
        if present:
            raise LabError(f"{name}: forbidden Compose options: {', '.join(sorted(present))}")
        policy = definition.get("network_policy", {})
        dns_policy = policy.get("boundaries", {}).get("dns", {}) if isinstance(policy, dict) else {}
        proxy_policy = policy.get("boundaries", {}).get("proxies", {}) if isinstance(policy, dict) else {}
        if dns_policy.get("mode") == "deny" and any(key in service for key in ("dns", "dns_search", "dns_opt")):
            raise LabError(f"{name}: DNS configuration conflicts with the selected deny policy")
        proxy_keys = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
        environment = service.get("environment", {})
        environment_keys = set(environment) if isinstance(environment, dict) else {
            str(item).split("=", 1)[0] for item in environment if isinstance(item, str)
        } if isinstance(environment, list) else set()
        if proxy_policy.get("mode") == "deny" and proxy_keys.intersection(environment_keys):
            raise LabError(f"{name}: proxy environment conflicts with the selected deny policy")
        image = service.get("image")
        if not isinstance(image, str) or not image.strip():
            raise LabError(f"{name}: an explicit pre-acquired image is required; build is forbidden")
        if service.get("pull_policy") not in (None, "never"):
            raise LabError(f"{name}: pull_policy must be absent or 'never'")
        if service.get("ports") or service.get("network_mode") == "host":
            raise LabError(f"{name}: published ports and host networking are forbidden")
        if service.get("privileged") is True or service.get("cap_add"):
            raise LabError(f"{name}: privileged execution or added capabilities are forbidden")
        cap_drop = service.get("cap_drop", [])
        if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
            raise LabError(f"{name}: cap_drop must be a list containing ALL")
        security_opt = service.get("security_opt", [])
        if not isinstance(security_opt, list) or "no-new-privileges:true" not in security_opt:
            raise LabError(f"{name}: no-new-privileges is required")
        if any("unconfined" in str(option).lower() or "label=disable" in str(option).lower() for option in security_opt):
            raise LabError(f"{name}: unconfined security profiles are forbidden")
        user = service.get("user")
        if service.get("read_only") is not True or user in (None, "root", 0):
            raise LabError(f"{name}: read-only root and explicit non-root user are required")
        if isinstance(user, str) and re.match(r"^(?:0|root)(?::0)?$", user.strip()):
            raise LabError(f"{name}: root execution is forbidden")
        _memory_limit_mib(service.get("mem_limit"), f"{name}.mem_limit")
        require_integer(service.get("pids_limit"), f"{name}.pids_limit", 1)
        cpus = service.get("cpus")
        if type(cpus) not in (int, float) or cpus <= 0:
            raise LabError(f"{name}.cpus must be a positive CPU limit")
        if service.get("deploy") is not None:
            raise LabError(f"{name}: deploy overrides are not permitted; use explicit bounded service limits")
        if service.get("restart") not in (None, "no"):
            raise LabError(f"{name}: automatic restart policies are forbidden")
        if service.get("read_only") is not True:
            raise LabError(f"{name}: read-only root filesystem is required")

        attachments = service.get("networks", [])
        if not isinstance(attachments, (list, dict)):
            raise LabError(f"{name}.networks must be a list or mapping")
        if set(attachments) != {logical}:
            raise LabError(f"{name}: service must attach only to the declared internal network")
        if service.get("tmpfs"):
            entries = service["tmpfs"]
            if isinstance(entries, str):
                values = [entries]
            elif isinstance(entries, list):
                values = entries
            else:
                raise LabError(f"{name}.tmpfs must be a string or list")
            for entry in values:
                text = str(entry)
                if not re.search(r"(?:^|[:;,])size=[1-9][0-9]*[kKmMgG]?(?:[,;]|$)", text):
                    raise LabError(f"{name}: each tmpfs mount must have an explicit size limit")
    return document


__all__ = ["validate_compose_document"]
