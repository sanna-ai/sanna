"""Shared test configuration and constants for Sanna test suite.

Sets SANNA_CONSTITUTION_PUBLIC_KEY env var so that all tests using
@sanna_observe with pre-built signed constitutions pass cryptographic
verification by default (CRIT-02).
"""

import os
from pathlib import Path

# All pre-built test constitutions share this signing key
TESTS_DIR = Path(__file__).parent
TEST_PUBLIC_KEY = str(
    TESTS_DIR / ".test_keys"
    / "003f07d057a118906bb85c97a4e9173dfffe040cae77bd85362011d8b880ccbf.pub"
)

# Set environment variable so sanna_observe can find the key automatically.
# This is the env var fallback for constitution_public_key_path.
os.environ.setdefault("SANNA_CONSTITUTION_PUBLIC_KEY", TEST_PUBLIC_KEY)

# Allow ReceiptStore to use pytest tmp_path (which lives under /tmp).
# Without this, ReceiptStore rejects /tmp paths as insecure in CI.
os.environ.setdefault("SANNA_ALLOW_TEMP_DB", "1")
