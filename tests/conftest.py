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
    / "c7065a8b70d9ad93611125691c762cedbef6c15e8f4fc25a86cabb4ceecbd3d8.pub"
)

# Set environment variable so sanna_observe can find the key automatically.
# This is the env var fallback for constitution_public_key_path.
os.environ.setdefault("SANNA_CONSTITUTION_PUBLIC_KEY", TEST_PUBLIC_KEY)
