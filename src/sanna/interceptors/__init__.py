"""Sanna execution surface interceptors.

Patches runtime libraries to enforce governance on subprocess and HTTP calls.
"""

from .subprocess_interceptor import patch_subprocess, unpatch_subprocess
from .http_interceptor import patch_http, unpatch_http

__all__ = [
    "patch_subprocess",
    "unpatch_subprocess",
    "patch_http",
    "unpatch_http",
]
