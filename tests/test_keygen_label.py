"""Tests for sanna-keygen --label feature (v0.9.1).

Covers:
- Label stored in meta.json
- Meta.json always created
- load_key_metadata utility
- Key files named by key_id
- Backward compatibility
- Special characters in label
"""

import json

import pytest

from sanna.crypto import (
    generate_keypair,
    load_key_metadata,
    load_public_key,
    compute_key_id,
    sign_bytes,
    verify_signature,
    load_private_key,
)


class TestKeygenLabel:
    """Tests for --label flag on sanna-keygen."""

    def test_keygen_with_label_creates_meta_with_label(self, tmp_path):
        """keygen with --label creates meta.json containing the label."""
        _, pub_path = generate_keypair(tmp_path, label="author")
        meta = load_key_metadata(pub_path)
        assert meta is not None
        assert meta["label"] == "author"

    def test_keygen_without_label_creates_meta_without_label(self, tmp_path):
        """keygen without --label creates meta.json but omits label field."""
        _, pub_path = generate_keypair(tmp_path)
        meta = load_key_metadata(pub_path)
        assert meta is not None
        assert "label" not in meta

    def test_meta_always_has_key_id_created_at_algorithm(self, tmp_path):
        """meta.json always contains key_id, created_at, algorithm."""
        _, pub_path = generate_keypair(tmp_path)
        meta = load_key_metadata(pub_path)
        assert meta is not None
        assert "key_id" in meta
        assert len(meta["key_id"]) == 64
        assert "created_at" in meta
        assert meta["algorithm"] == "Ed25519"

    def test_load_key_metadata_returns_correct_data(self, tmp_path):
        """load_key_metadata returns correct data when meta.json exists."""
        priv_path, pub_path = generate_keypair(tmp_path, label="gateway")
        # Can load from either .key or .pub path
        meta_from_pub = load_key_metadata(pub_path)
        meta_from_priv = load_key_metadata(priv_path)
        assert meta_from_pub == meta_from_priv
        assert meta_from_pub["label"] == "gateway"
        assert meta_from_pub["algorithm"] == "Ed25519"

    def test_load_key_metadata_returns_none_when_missing(self, tmp_path):
        """load_key_metadata returns None when meta.json doesn't exist."""
        # Create a fake key file with no meta.json
        fake_key = tmp_path / "fake.pub"
        fake_key.write_text("fake")
        assert load_key_metadata(fake_key) is None

    def test_keys_with_meta_still_work_for_signing(self, tmp_path):
        """Keys generated with meta.json still work for signing/verification."""
        priv_path, pub_path = generate_keypair(tmp_path, label="signer")
        priv_key = load_private_key(priv_path)
        pub_key = load_public_key(pub_path)

        data = b"test data to sign"
        sig = sign_bytes(data, priv_key)
        assert verify_signature(data, sig, pub_key)

    def test_label_with_special_characters(self, tmp_path):
        """Label with spaces and unicode works correctly."""
        _, pub_path = generate_keypair(tmp_path, label="VP Risk Officer")
        meta = load_key_metadata(pub_path)
        assert meta["label"] == "VP Risk Officer"

    def test_label_with_unicode(self, tmp_path):
        """Label with unicode characters works correctly."""
        _, pub_path = generate_keypair(tmp_path, label="approver-日本語")
        meta = load_key_metadata(pub_path)
        assert meta["label"] == "approver-日本語"

    def test_key_files_named_by_key_id(self, tmp_path):
        """Key files are named <key_id>.key and <key_id>.pub."""
        priv_path, pub_path = generate_keypair(tmp_path)
        pub_key = load_public_key(pub_path)
        key_id = compute_key_id(pub_key)
        assert priv_path.name == f"{key_id}.key"
        assert pub_path.name == f"{key_id}.pub"

    def test_meta_json_named_by_key_id(self, tmp_path):
        """Meta.json is named <key_id>.meta.json."""
        _, pub_path = generate_keypair(tmp_path)
        key_id = pub_path.stem
        meta_path = pub_path.parent / f"{key_id}.meta.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["key_id"] == key_id
