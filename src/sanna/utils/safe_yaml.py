"""Safe YAML loading with duplicate key detection.

Security rationale
------------------
PyYAML's ``safe_load()`` silently overwrites duplicate mapping keys (last-wins
semantics), mirroring the same ambiguity as ``json.loads()``.  An attacker can
craft a constitution YAML with two ``invariants:`` keys -- the first version
might appear in a code review while the second silently takes effect.

This module provides a custom SafeLoader subclass that raises on duplicate
keys at any mapping level.
"""

from __future__ import annotations

from typing import IO, Union

import yaml


class _DuplicateKeyCheckLoader(yaml.SafeLoader):
    """SafeLoader subclass that rejects duplicate mapping keys."""


def _construct_mapping_no_duplicates(loader, node):
    """Construct a mapping, raising on duplicate keys."""
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node)
    seen: set = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError(
                f"Duplicate YAML key: {key!r} "
                f"(line {node.start_mark.line + 1})"
            )
        seen.add(key)
    return dict(pairs)


_DuplicateKeyCheckLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)


def safe_yaml_load(stream: Union[str, IO[str]]) -> object:
    """Load YAML with duplicate key rejection.

    Drop-in replacement for ``yaml.safe_load()`` that raises
    ``ValueError`` when any mapping contains a duplicate key.
    """
    return yaml.load(stream, Loader=_DuplicateKeyCheckLoader)
