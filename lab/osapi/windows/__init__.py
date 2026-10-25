"""Read-only Windows host observations through PowerShell networking cmdlets."""

from .firewall import inspect_firewall
from .interfaces import inspect_interfaces
from .processes import inspect_processes
from .routes import inspect_routes
from .sockets import inspect_sockets

__all__ = [
    "inspect_firewall",
    "inspect_interfaces",
    "inspect_processes",
    "inspect_routes",
    "inspect_sockets",
]
