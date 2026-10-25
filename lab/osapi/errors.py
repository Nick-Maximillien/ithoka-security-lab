"""Errors used by the OS API without hiding command failure details."""


class OSAPIError(RuntimeError):
    """An OS operation failed or returned unusable data."""


class UnsupportedPlatformError(OSAPIError):
    """The requested native interface is unavailable on this platform."""
