"""Cloud client subpackage.

Anticipated future modules (DVR resolvers, agent registry, etc.) live alongside
constitution.py. Each module has a focused responsibility; this package is not
a single CloudClient class.
"""

from sanna.cloud.constitution import load_constitution_from_cloud

__all__ = ["load_constitution_from_cloud"]
