"""Sanna execution surface interceptors.

Patches runtime libraries to enforce governance on subprocess and HTTP calls.
"""

from .subprocess_interceptor import patch_subprocess, unpatch_subprocess

__all__ = ["patch_subprocess", "unpatch_subprocess"]
