"""AdGuard DNS CLI -- pull blocked DNS requests per device."""

__version__ = "1.0.0"

from .api import AdGuardDNSClient, ApiError, Device, QueryLogItem  # noqa: F401

__all__ = ["AdGuardDNSClient", "ApiError", "Device", "QueryLogItem", "__version__"]
