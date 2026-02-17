"""
CLI entry points for sanna-generate and sanna-verify commands.
Legacy aliases: c3m-receipt, c3m-verify
"""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .receipt import generate_receipt, SannaReceipt, TOOL_VERSION
from .verify import verify_receipt, load_schema, VerificationResult


# =============================================================================
# RECEIPT CLI
# =============================================================================

def format_receipt_summary(receipt: SannaReceipt) -> str:
    """Format receipt as human-readable summary."""
    lines = [
        "=" * 60,
        "SANNA REASONING RECEIPT",
        "=" * 60,
        f"Tool:        v{receipt.tool_version}",
        f"Schema:      v{receipt.schema_version}",
        f"Checks:      v{receipt.checks_version}",
        f"Receipt ID:  {receipt.receipt_id}",
        f"Fingerprint: {receipt.receipt_fingerprint}",
        f"Trace ID:    {receipt.trace_id}",
        f"Generated:   {receipt.timestamp}",
        "",
        f"Status:      {receipt.coherence_status}",
        f"Passed:      {receipt.checks_passed}/{receipt.checks_passed + receipt.checks_failed}",
        "",
        "-" * 60,
        "CONSISTENCY CHECKS",
        "-" * 60,
    ]

    for check in receipt.checks:
        icon = "✓" if check["passed"] else "✗"
        lines.append(f"  [{icon}] {check['check_id']}: {check['name']}")
        if not check["passed"] and check.get("evidence"):
            lines.append(f"      └─ {check['evidence']}")

    prov = receipt.final_answer_provenance
    prov_str = prov.get("source", "unknown")
    if prov.get("span_name"):
        prov_str += f" ({prov['span_name']})"
    elif prov.get("field"):
        prov_str += f" [{prov['field']}]"

    lines.extend([
        "",
        "-" * 60,
        "PROVENANCE",
        "-" * 60,
        f"  Context Hash:  {receipt.context_hash}",
        f"  Output Hash:   {receipt.output_hash}",
        f"  Answer Source: {prov_str}",
        "",
        "=" * 60,
    ])

    return "\n".join(lines)


def main_generate():
    """Entry point for sanna-generate command.

    Generates a receipt from a JSON trace-data file.
    """
    parser = argparse.ArgumentParser(
        description="Generate a Sanna reasoning receipt from a trace-data JSON file"
    )
    parser.add_argument("trace_file", help="Path to trace-data JSON file")
    parser.add_argument("--format", choices=["summary", "json"], default="summary",
                       help="Output format (default: summary)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--version", action="version", version=f"sanna-generate {TOOL_VERSION}")

    args = parser.parse_args()

    # Load trace data from JSON file
    try:
        with open(args.trace_file) as f:
            trace_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.trace_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1

    # Generate receipt
    receipt = generate_receipt(trace_data)

    # Format output
    if args.format == "json":
        output = json.dumps(asdict(receipt), indent=2)
    else:
        output = format_receipt_summary(receipt)

    # Write output
    if args.output:
        from .utils.safe_io import atomic_write_text_sync
        atomic_write_text_sync(Path(args.output), output)
        print(f"Receipt written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0 if receipt.coherence_status != "FAIL" else 1


# =============================================================================
# VERIFY CLI
# =============================================================================

VERIFIER_VERSION = "0.3.0"


def format_verify_summary(result: VerificationResult, receipt: dict) -> str:
    """Format verification result as human-readable summary."""
    # Check for extensions
    extensions = receipt.get("extensions")
    if extensions:
        ext_count = len(extensions)
        ext_status = f"✓ Present ({ext_count} keys, ignored)"
    else:
        ext_status = "None"

    lines = [
        "=" * 50,
        "SANNA RECEIPT VERIFICATION",
        "=" * 50,
        "",
        f"Status:      {'✓ VALID' if result.valid else '✗ INVALID'}",
        f"Schema:      v{receipt.get('schema_version', '?')}",
        f"Fingerprint: {'✓ Match' if result.computed_fingerprint == result.expected_fingerprint else '✗ Mismatch'}",
        f"Consistency: {'✓ OK' if result.computed_status == result.expected_status else '✗ Mismatch'}",
        f"Extensions:  {ext_status}",
    ]

    if result.errors:
        lines.extend([
            "",
            "-" * 50,
            "ERRORS",
            "-" * 50,
        ])
        for err in result.errors[:5]:  # Max 5 errors
            lines.append(f"  • {err}")

    if result.warnings:
        lines.extend([
            "",
            "-" * 50,
            "WARNINGS",
            "-" * 50,
        ])
        for warn in result.warnings[:3]:
            lines.append(f"  • {warn}")

    # Receipt Triad section (Block I — v2 gateway receipts)
    extensions = receipt.get("extensions") or {}
    gw_v2 = extensions.get("gateway_v2") or {}
    triad = gw_v2.get("receipt_triad")
    if triad and isinstance(triad, dict):
        from sanna.verify import verify_receipt_triad
        tv = verify_receipt_triad(receipt)
        lines.extend([
            "",
            "-" * 50,
            "RECEIPT TRIAD",
            "-" * 50,
        ])
        ih = triad.get("input_hash", "")
        rh = triad.get("reasoning_hash", "")
        ah = triad.get("action_hash", "")

        ih_icon = "✓" if tv.input_hash_valid else "✗"
        rh_icon = "✓" if tv.reasoning_hash_valid else "✗"
        ah_icon = "✓" if tv.action_hash_valid else "✗"

        lines.append(f"  Input     (Hash A): {ih[:24]}... {ih_icon}")
        lines.append(f"  Reasoning (Hash B): {rh[:24]}... {rh_icon}")
        lines.append(f"  Action    (Hash C): {ah[:24]}... {ah_icon}")

        if tv.input_hash_match is True:
            lines.append(f"  Input hash: ✓ matches content")
        elif tv.input_hash_match is False:
            lines.append(f"  Input hash: ✗ MISMATCH (stored vs recomputed)")

        if tv.gateway_boundary_consistent:
            lines.append(f"  Binding:  Input → Reasoning → Action [VERIFIED]")
        elif tv.context_limitation == "gateway_boundary":
            lines.append(f"  Binding:  ✗ FAILED (input_hash != action_hash)")

        ctx = triad.get("context_limitation", "")
        if ctx:
            lines.append(f"  Context:  {ctx}")
            lines.append(
                f"  Note:     Action hash reflects what the gateway "
                f"forwarded, not what the downstream executed."
            )

    # Identity verification section
    iv = receipt.get("identity_verification")
    if iv and isinstance(iv, dict):
        lines.extend([
            "",
            "-" * 50,
            "IDENTITY CLAIMS",
            "-" * 50,
        ])
        for claim in iv.get("claims", []):
            status = claim.get("status", "unknown")
            icon = "✓" if status == "verified" else ("✗" if status == "failed" else "?")
            lines.append(
                f"  {icon} {claim['provider']}/{claim['claim_type']} "
                f"({claim['credential_id']}): {status}"
            )
        total = iv.get("total_claims", 0)
        verified = iv.get("verified", 0)
        lines.append(f"  Summary: {verified}/{total} verified")

    lines.extend(["", "=" * 50])
    return "\n".join(lines)


def format_verify_json(result: VerificationResult, receipt: dict) -> str:
    """Format verification result as JSON."""
    output = {
        "valid": result.valid,
        "exit_code": result.exit_code,
        "schema_version": receipt.get("schema_version"),
        "receipt_id": receipt.get("receipt_id"),
        "fingerprint_match": result.computed_fingerprint == result.expected_fingerprint,
        "status_match": result.computed_status == result.expected_status,
        "errors": result.errors,
        "warnings": result.warnings,
    }
    return json.dumps(output, indent=2)


def main_verify():
    """Entry point for sanna-verify command."""
    parser = argparse.ArgumentParser(
        description="Verify Sanna reasoning receipts",
        epilog="Exit codes: 0=valid, 2=schema invalid, 3=fingerprint mismatch, 4=consistency error, 5=other"
    )
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument("--format", choices=["summary", "json"], default="summary",
                       help="Output format (default: summary)")
    parser.add_argument("--schema", help="Path to schema file (optional, auto-detected)")
    parser.add_argument("--public-key", help="Path to Ed25519 public key for receipt signature verification")
    parser.add_argument("--constitution", help="Path to constitution file for chain verification")
    parser.add_argument("--constitution-public-key", help="Path to Ed25519 public key for constitution signature verification")
    parser.add_argument("--approver-public-key", help="Path to Ed25519 public key for approval signature verification")
    parser.add_argument("--version", action="version", version=f"sanna-verify {VERIFIER_VERSION}")

    args = parser.parse_args()

    # Load receipt
    try:
        with open(args.receipt) as f:
            receipt = json.load(f)
    except FileNotFoundError:
        print(f"Error: Receipt file not found: {args.receipt}", file=sys.stderr)
        return 5
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in receipt: {e}", file=sys.stderr)
        return 5

    # Load schema
    try:
        schema = load_schema(args.schema)
    except FileNotFoundError as e:
        print(f"Error: Schema not found: {e}", file=sys.stderr)
        return 5

    # Verify
    result = verify_receipt(
        receipt, schema,
        public_key_path=args.public_key,
        constitution_path=args.constitution,
        constitution_public_key_path=args.constitution_public_key,
        approver_public_key_path=args.approver_public_key,
    )

    # Output
    if args.format == "json":
        print(format_verify_json(result, receipt))
    else:
        print(format_verify_summary(result, receipt))

    return result.exit_code


# =============================================================================
# CONSTITUTION CLI
# =============================================================================

def main_init_constitution():
    """Entry point for sanna-init-constitution command."""
    parser = argparse.ArgumentParser(
        description="Scaffold a new Sanna constitution YAML file"
    )
    parser.add_argument("--output", "-o", default="constitution.yaml",
                       help="Output file path (default: constitution.yaml)")
    parser.add_argument("--version", action="version", version=f"sanna-init-constitution {TOOL_VERSION}")

    args = parser.parse_args()

    output_path = Path(args.output)
    if output_path.exists():
        print(f"Error: File already exists: {output_path}", file=sys.stderr)
        print("Remove it first or choose a different name with --output.", file=sys.stderr)
        return 1

    from .constitution import scaffold_constitution
    scaffold_constitution(output_path)

    print(f"Created {output_path}")
    print()
    print("Next steps:")
    print(f"  1. Edit {output_path} with your agent's boundaries and governance details")
    print("  2. Get approval from your compliance/risk team")
    print(f"  3. Sign it:  sanna-sign-constitution {output_path} --private-key <your-key-id>.key")
    print(f'  4. Wire it:  @sanna_observe(constitution_path="{output_path}")')
    return 0


def main_hash_constitution():
    """Entry point for sanna-hash-constitution command.

    Computes policy_hash only (no Ed25519 cryptographic signature).
    """
    parser = argparse.ArgumentParser(
        description="Validate and hash a Sanna constitution file (no Ed25519 signing)"
    )
    parser.add_argument("constitution", help="Path to constitution YAML/JSON file")
    parser.add_argument("--output", "-o", help="Output file (default: overwrites input)")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of YAML")
    parser.add_argument("--version", action="version", version=f"sanna-hash-constitution {TOOL_VERSION}")

    args = parser.parse_args()

    from .constitution import (
        load_constitution, sign_constitution, save_constitution,
        SannaConstitutionError,
    )

    # Load and validate
    try:
        constitution = load_constitution(args.constitution, validate=True)
    except SannaConstitutionError as e:
        msg = str(e)
        if "hash mismatch" in msg.lower():
            print(f"Error: Constitution content does not match policy_hash. Re-hash with sanna-hash-constitution first.", file=sys.stderr)
        elif "schema" in msg.lower():
            print(f"Error: Constitution schema validation failed: {e}", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: Constitution file not found: {args.constitution}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: Constitution missing required field: {e}", file=sys.stderr)
        return 1

    # Hash only (no Ed25519)
    signed = sign_constitution(constitution)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    elif args.json:
        output_path = Path(args.constitution).with_suffix(".json")
    else:
        output_path = Path(args.constitution)

    if args.json:
        output_path = output_path.with_suffix(".json")

    save_constitution(signed, output_path)

    print(f"Constitution hashed (NOT cryptographically signed).")
    print(f"  File:       {output_path}")
    print(f"  Agent:      {signed.identity.agent_name}")
    print(f"  Hash:       {signed.policy_hash}")
    print()
    print("To add Ed25519 cryptographic signature:")
    print(f"  sanna-sign-constitution {output_path} --private-key <your-key-id>.key")

    return 0


def main_sign_constitution():
    """Entry point for sanna-sign-constitution command."""
    parser = argparse.ArgumentParser(
        description="Validate and sign a Sanna constitution file with Ed25519"
    )
    parser.add_argument("constitution", help="Path to constitution YAML/JSON file")
    parser.add_argument("--output", "-o", help="Output file (default: overwrites input)")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of YAML")
    parser.add_argument("--private-key",
                       help="Path to Ed25519 private key for cryptographic signing (required for signing)")
    parser.add_argument("--signed-by", help="Identity of the signer (e.g., email)")
    parser.add_argument("--verify-only", action="store_true",
                       help="Validate and show summary without signing")
    parser.add_argument("--version", action="version", version=f"sanna-sign-constitution {TOOL_VERSION}")

    args = parser.parse_args()

    from .constitution import (
        load_constitution, sign_constitution, save_constitution,
        constitution_to_receipt_ref, constitution_to_dict, SannaConstitutionError,
    )

    # Load and validate (bypass hash check for unsigned constitutions)
    try:
        constitution = load_constitution(args.constitution, validate=True)
    except SannaConstitutionError as e:
        msg = str(e)
        if "hash mismatch" in msg.lower():
            print(f"Error: Constitution content does not match policy_hash. Re-hash with sanna-hash-constitution first.", file=sys.stderr)
        elif "schema" in msg.lower():
            print(f"Error: Constitution schema validation failed: {e}", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: Constitution file not found: {args.constitution}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: Constitution missing required field: {e}", file=sys.stderr)
        return 1

    if args.verify_only:
        print("=" * 50)
        print("SANNA CONSTITUTION SUMMARY")
        print("=" * 50)
        print(f"  Agent:      {constitution.identity.agent_name}")
        print(f"  Domain:     {constitution.identity.domain}")
        print(f"  Author:     {constitution.provenance.authored_by}")
        print(f"  Approvers:  {', '.join(constitution.provenance.approved_by)}")
        print(f"  Approved:   {constitution.provenance.approval_date}")
        print(f"  Method:     {constitution.provenance.approval_method}")
        print(f"  Boundaries: {len(constitution.boundaries)}")
        print(f"  Halt rules: {len(constitution.halt_conditions)}")
        print(f"  Invariants: {len(constitution.invariants)}")
        if constitution.policy_hash:
            print(f"  Hash:       {constitution.policy_hash}")
            sig = constitution.provenance.signature
            if sig and sig.value:
                print(f"  Key ID:     {sig.key_id}")
                print(f"  Signed by:  {sig.signed_by}")
                print(f"  Scheme:     {sig.scheme}")
        else:
            print("  Status:     UNSIGNED")
        print("=" * 50)
        print()
        print("Validation: PASSED")
        return 0

    # Sign with Ed25519
    if not args.private_key:
        print("Error: --private-key is required for signing. Use --verify-only to validate without signing.", file=sys.stderr)
        return 1

    signed = sign_constitution(
        constitution,
        private_key_path=args.private_key,
        signed_by=args.signed_by,
    )

    # Determine output path and format
    if args.output:
        output_path = Path(args.output)
    elif args.json:
        output_path = Path(args.constitution).with_suffix(".json")
    else:
        output_path = Path(args.constitution)

    if args.json:
        output_path = output_path.with_suffix(".json")

    save_constitution(signed, output_path)

    sig = signed.provenance.signature
    print(f"Signed constitution written to {output_path}")
    print()
    print(f"  Agent:     {signed.identity.agent_name}")
    print(f"  Hash:      {signed.policy_hash}")
    if sig and sig.value:
        print(f"  Key ID:    {sig.key_id}")
        print(f"  Signed by: {sig.signed_by}")
        print(f"  Scheme:    {sig.scheme}")
    print(f"  Approvers: {', '.join(signed.provenance.approved_by)}")
    print()
    print("Receipt reference preview:")
    ref = constitution_to_receipt_ref(signed)
    print(json.dumps(ref, indent=2))
    print()
    print("Next step:")
    print(f'  @sanna_observe(constitution_path="{output_path}")')

    return 0


def main_keygen():
    """Entry point for sanna-keygen command."""
    parser = argparse.ArgumentParser(
        description="Generate Ed25519 keypair for Sanna constitution and receipt signing"
    )
    parser.add_argument("--output-dir", "-o", default=None,
                       help="Directory for key files (default: ~/.sanna/keys)")
    parser.add_argument("--label", help="Human-friendly label for the keypair (e.g. 'author', 'approver')")
    parser.add_argument("--signed-by", help="Human-readable signer identity (stored in meta.json)")
    parser.add_argument("--version", action="version", version=f"sanna-keygen {TOOL_VERSION}")

    args = parser.parse_args()

    from .crypto import generate_keypair, load_key_metadata

    output_dir = args.output_dir
    if output_dir is None:
        output_dir = str(Path.home() / ".sanna" / "keys")
        from .utils.safe_io import ensure_secure_dir
        ensure_secure_dir(Path(output_dir))

    private_path, public_path = generate_keypair(
        output_dir,
        signed_by=args.signed_by,
        label=args.label,
    )

    # Read back metadata to get key_id for display
    meta = load_key_metadata(public_path)
    key_id = meta["key_id"] if meta else private_path.stem

    if args.label:
        print(f"Generated Ed25519 keypair '{args.label}' ({key_id[:16]}...)")
    else:
        print(f"Generated Ed25519 keypair ({key_id[:16]}...)")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")
    meta_path = private_path.with_suffix(".meta.json")
    print(f"  Metadata:    {meta_path}")
    if args.signed_by:
        print(f"  Identity:    {args.signed_by}")
    print()
    print("Usage:")
    print(f"  sanna-sign-constitution constitution.yaml --private-key {private_path}")
    print(f"  sanna-verify-constitution constitution.yaml --public-key {public_path}")
    print()
    print("IMPORTANT: Keep the private key secure. Share only the public key.")

    return 0


def main_verify_constitution():
    """Entry point for sanna-verify-constitution command."""
    parser = argparse.ArgumentParser(
        description="Verify a Sanna constitution's integrity and signature"
    )
    parser.add_argument("constitution", help="Path to constitution YAML/JSON file")
    parser.add_argument("--public-key", help="Path to Ed25519 public key for signature verification")
    parser.add_argument("--identity-provider-keys",
                       help="Comma-separated key_id=path pairs for identity claim verification "
                            "(e.g., 'trulioo-key=trulioo.pub,ops-key=ops.pub')")
    parser.add_argument("--version", action="version", version=f"sanna-verify-constitution {TOOL_VERSION}")

    args = parser.parse_args()

    from .constitution import load_constitution, compute_constitution_hash, SannaConstitutionError

    # Load and validate
    try:
        constitution = load_constitution(args.constitution)
    except SannaConstitutionError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 2

    if not constitution.policy_hash:
        print("FAILED: Constitution is not signed (no policy_hash).", file=sys.stderr)
        return 1

    # Verify hash
    computed = compute_constitution_hash(constitution)
    if computed != constitution.policy_hash:
        print(f"FAILED: Hash mismatch. File has been modified since signing.", file=sys.stderr)
        return 1

    print(f"Hash:     VALID ({constitution.policy_hash[:16]}...)")

    # Verify Ed25519 signature if public key provided
    if args.public_key:
        sig = constitution.provenance.signature
        if not sig or not sig.value:
            print("FAILED: Constitution has no Ed25519 signature.", file=sys.stderr)
            return 1

        from .crypto import verify_constitution_full
        valid = verify_constitution_full(constitution, args.public_key)
        if not valid:
            print("Signature: FAILED — signature does not match public key.", file=sys.stderr)
            return 1
        print(f"Signature: VALID (key_id={sig.key_id}, scheme={sig.scheme})")
    else:
        sig = constitution.provenance.signature
        if sig and sig.value:
            print(f"Signature: PRESENT (key_id={sig.key_id}) — provide --public-key to verify")

    print(f"Agent:    {constitution.identity.agent_name}")

    # Identity claims section
    claims = constitution.identity.identity_claims
    if claims:
        print(f"Identity Claims: {len(claims)} claims found")
        if args.identity_provider_keys:
            # Parse key_id=path pairs
            provider_keys: dict[str, str] = {}
            for pair in args.identity_provider_keys.split(","):
                pair = pair.strip()
                if "=" in pair:
                    kid, kpath = pair.split("=", 1)
                    provider_keys[kid.strip()] = kpath.strip()

            from .constitution import verify_identity_claims
            summary = verify_identity_claims(constitution.identity, provider_keys)
            for r in summary.results:
                icon = "✓" if r.status == "verified" else ("✗" if r.status == "failed" else "?")
                print(f"  {icon} {r.claim.provider}/{r.claim.claim_type} ({r.claim.credential_id}): {r.status}")
                if r.detail and r.status != "verified":
                    print(f"      {r.detail}")
        else:
            for c in claims:
                print(f"  - {c.provider}/{c.claim_type} ({c.credential_id})")
            print("  Note: Use --identity-provider-keys to verify claim signatures.")

    print(f"Status:   VERIFIED")

    return 0


# =============================================================================
# BUNDLE CLI
# =============================================================================

def main_create_bundle():
    """Entry point for sanna-create-bundle command."""
    parser = argparse.ArgumentParser(
        description="Create a Sanna evidence bundle (.zip) for offline verification"
    )
    parser.add_argument("--receipt", required=True, help="Path to signed receipt JSON")
    parser.add_argument("--constitution", required=True, help="Path to signed constitution YAML")
    parser.add_argument("--public-key", required=True, help="Path to Ed25519 public key (PEM)")
    parser.add_argument("--output", "-o", required=True, help="Output path for the bundle zip")
    parser.add_argument("--description", help="Human-readable description for metadata")
    parser.add_argument("--approver-public-key", help="Path to approver's Ed25519 public key for approval verification")
    parser.add_argument("--version", action="version", version=f"sanna-create-bundle {TOOL_VERSION}")

    args = parser.parse_args()

    try:
        from .bundle import create_bundle
        bundle_path = create_bundle(
            receipt_path=args.receipt,
            constitution_path=args.constitution,
            public_key_path=args.public_key,
            output_path=args.output,
            description=args.description,
            approver_public_key_path=args.approver_public_key,
        )
        print(f"Bundle created: {bundle_path}")
        print(f"  Receipt:      {args.receipt}")
        print(f"  Constitution: {args.constitution}")
        print(f"  Public key:   {args.public_key}")
        return 0
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main_verify_bundle():
    """Entry point for sanna-verify-bundle command."""
    parser = argparse.ArgumentParser(
        description="Verify a Sanna evidence bundle",
        epilog="Exit codes: 0=valid, 1=invalid"
    )
    parser.add_argument("bundle", help="Path to .zip evidence bundle")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Show detail for each verification step")
    parser.add_argument("--version", action="version", version=f"sanna-verify-bundle {TOOL_VERSION}")

    args = parser.parse_args()

    try:
        from .bundle import verify_bundle

        result = verify_bundle(args.bundle)

        if args.json:
            output = {
                "valid": result.valid,
                "checks": [
                    {"name": c.name, "passed": c.passed, "detail": c.detail}
                    for c in result.checks
                ],
                "receipt_summary": result.receipt_summary,
                "errors": result.errors,
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Bundle: {args.bundle}")
            for check in result.checks:
                icon = "\u2713" if check.passed else "\u2717"
                line = f"  {icon} {check.name}"
                if args.verbose:
                    line += f" — {check.detail}"
                elif not check.passed:
                    line += f" — {check.detail}"
                print(line)

            print()
            verdict = "VALID" if result.valid else "INVALID"
            print(f"VERDICT: {verdict}")

            summary = result.receipt_summary
            if summary:
                if summary.get("agent_name"):
                    print(f"Agent: {summary['agent_name']}")
                if summary.get("coherence_status"):
                    print(f"Decision: {summary['coherence_status']}")
                if summary.get("constitution_version"):
                    print(f"Constitution: v{summary['constitution_version']}")

        return 0 if result.valid else 1

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


# =============================================================================
# DRIFT REPORT CLI
# =============================================================================

def main_drift_report():
    """Entry point for sanna-drift-report command."""
    parser = argparse.ArgumentParser(
        description="Governance drift report over stored Sanna receipts"
    )
    parser.add_argument("--db", default=".sanna/receipts.db",
                       help="Path to receipt store DB (default: .sanna/receipts.db)")
    parser.add_argument("--window", type=int, action="append", dest="windows",
                       help="Analysis window in days (repeatable, default: 30)")
    parser.add_argument("--agent", action="append", dest="agents",
                       help="Filter to specific agent ID (repeatable)")
    parser.add_argument("--threshold", type=float, default=0.15,
                       help="Failure-rate threshold 0–1 (default: 0.15)")
    parser.add_argument("--projection-days", type=int, default=90,
                       help="Projection horizon in days (default: 90)")
    parser.add_argument("--json", action="store_true",
                       help="Machine-readable JSON output")
    parser.add_argument("--export", choices=["json", "csv"], default=None,
                       help="Export format (json or csv)")
    parser.add_argument("--output", default=None,
                       help="Output file path (used with --export)")
    parser.add_argument("--version", action="version", version=f"sanna-drift-report {TOOL_VERSION}")

    args = parser.parse_args()

    from .store import ReceiptStore
    from .drift import DriftAnalyzer, format_drift_report, export_drift_report, export_drift_report_to_file

    if not Path(args.db).exists():
        print(f"Error: Receipt store not found: {args.db}", file=sys.stderr)
        print("Run agents with ReceiptStore to populate it first.", file=sys.stderr)
        return 1

    store = ReceiptStore(args.db)
    analyzer = DriftAnalyzer(store)

    windows = args.windows or [30]
    agent_ids = args.agents or [None]

    reports = []
    for agent_id in agent_ids:
        if len(windows) > 1:
            batch = analyzer.analyze_multi(
                windows=windows,
                agent_id=agent_id,
                threshold=args.threshold,
                projection_days=args.projection_days,
            )
            reports.extend(batch)
        else:
            report = analyzer.analyze(
                window_days=windows[0],
                agent_id=agent_id,
                threshold=args.threshold,
                projection_days=args.projection_days,
            )
            reports.append(report)

    # Export mode: write to file or stdout in requested format
    if args.export:
        if args.output:
            if args.export == "json":
                from dataclasses import asdict as _asdict
                combined = json.dumps([_asdict(r) for r in reports], indent=2)
            else:
                # CSV: concatenate reports, skip header on 2nd+
                parts = []
                for i, report in enumerate(reports):
                    csv_text = export_drift_report(report, fmt="csv")
                    if i > 0:
                        # Strip header row from subsequent reports
                        lines = csv_text.split("\n", 1)
                        csv_text = lines[1] if len(lines) > 1 else ""
                    parts.append(csv_text)
                combined = "".join(parts)
            from .utils.safe_io import atomic_write_text_sync
            p = Path(args.output)
            p.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text_sync(p, combined)
            print(f"Exported {len(reports)} report(s) to {args.output}")
        else:
            for report in reports:
                print(export_drift_report(report, fmt=args.export))
    elif args.json:
        from dataclasses import asdict
        print(json.dumps([asdict(r) for r in reports], indent=2))
    else:
        for report in reports:
            print(format_drift_report(report))

    store.close()

    # Exit code: 1 if any fleet status is CRITICAL
    if any(r.fleet_status == "CRITICAL" for r in reports):
        return 1
    return 0


# =============================================================================
# DIFF CLI
# =============================================================================

def diff_cmd():
    """Entry point for sanna-diff command."""
    parser = argparse.ArgumentParser(
        description="Compare two Sanna constitutions and report governance changes"
    )
    parser.add_argument("old", help="Path to the old (baseline) constitution")
    parser.add_argument("new", help="Path to the new (target) constitution")
    parser.add_argument("--format", choices=["text", "json", "markdown"],
                       default="text", help="Output format (default: text)")
    parser.add_argument("--version", action="version", version=f"sanna-diff {TOOL_VERSION}")

    args = parser.parse_args()

    from .constitution import load_constitution
    from .constitution_diff import diff_constitutions

    try:
        old_const = load_constitution(args.old)
    except FileNotFoundError:
        print(f"Error: File not found: {args.old}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading old constitution: {e}", file=sys.stderr)
        return 1

    try:
        new_const = load_constitution(args.new)
    except FileNotFoundError:
        print(f"Error: File not found: {args.new}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading new constitution: {e}", file=sys.stderr)
        return 1

    result = diff_constitutions(old_const, new_const)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif args.format == "markdown":
        print(result.to_markdown())
    else:
        print(result.to_text())

    return 0


# =============================================================================
# APPROVE CONSTITUTION CLI
# =============================================================================

def approve_constitution_cmd():
    """Entry point for sanna-approve-constitution command."""
    parser = argparse.ArgumentParser(
        description="Approve a signed Sanna constitution with an Ed25519 signature"
    )
    parser.add_argument("constitution", help="Path to signed constitution YAML/JSON file")
    parser.add_argument("--approver-key", required=True,
                       help="Path to approver's Ed25519 private key (PEM)")
    parser.add_argument("--approver-id", required=True,
                       help="Email or identifier of the approver")
    parser.add_argument("--approver-role", required=True,
                       help="Human-readable role (e.g., 'VP Risk', 'CISO')")
    parser.add_argument("--version", dest="constitution_version", required=True,
                       help="Human-readable constitution version (e.g., '1', '2.0')")
    parser.add_argument("--tool-version", action="version", version=f"sanna-approve-constitution {TOOL_VERSION}")

    args = parser.parse_args()

    from .constitution import approve_constitution, SannaConstitutionError

    try:
        record = approve_constitution(
            constitution_path=args.constitution,
            approver_private_key=args.approver_key,
            approver_id=args.approver_id,
            approver_role=args.approver_role,
            constitution_version=args.constitution_version,
        )
    except SannaConstitutionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Constitution approved and written to {args.constitution}")
    print()
    print(f"  Approver:    {record.approver_id}")
    print(f"  Role:        {record.approver_role}")
    print(f"  Version:     {record.constitution_version}")
    print(f"  Content Hash: {record.content_hash[:16]}...")
    print(f"  Approved At: {record.approved_at}")
    if record.previous_version_hash:
        print(f"  Previous:    {record.previous_version_hash[:16]}...")

    return 0


# =============================================================================
# DEMO CLI
# =============================================================================

def main_demo():
    """Self-contained demo: generate keys, sign constitution, run agent, verify.

    No external dependencies required — everything runs in memory / tmp dir.
    """
    import os
    import tempfile
    import uuid

    from .constitution import (
        Constitution, AgentIdentity, Boundary, Invariant, Provenance,
        sign_constitution, save_constitution,
    )
    from .crypto import generate_keypair
    from .middleware import sanna_observe
    from .verify import verify_receipt

    parser = argparse.ArgumentParser(
        description="Run a self-contained Sanna governance demo"
    )
    parser.add_argument("--output-dir", "-o", default="./sanna-demo",
                       help="Directory for demo artifacts (default: ./sanna-demo)")
    parser.add_argument("--version", action="version", version=f"sanna-demo {TOOL_VERSION}")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=== Sanna Demo ===")
    print()

    # 1. Generate signing keys (in temp dir)
    with tempfile.TemporaryDirectory() as key_dir:
        priv_path, pub_path = generate_keypair(key_dir)
        print("1. Generated signing keys")

        # 2. Create minimal constitution
        const = Constitution(
            schema_version="0.1.0",
            identity=AgentIdentity(agent_name="demo-agent", domain="demo"),
            provenance=Provenance(
                authored_by="demo@sanna.dev",
                approved_by=["reviewer@sanna.dev"],
                approval_date="2026-01-01",
                approval_method="automated-demo",
            ),
            boundaries=[
                Boundary(id="B001", description="Operate within demo scope",
                        category="scope", severity="medium"),
            ],
            invariants=[
                Invariant(id="INV_NO_FABRICATION",
                         rule="Do not claim facts absent from sources.",
                         enforcement="halt"),
                Invariant(id="INV_MARK_INFERENCE",
                         rule="Clearly mark inferences.",
                         enforcement="warn"),
            ],
        )
        signed = sign_constitution(const, private_key_path=str(priv_path),
                                   signed_by="demo-signer")
        const_path = out_dir / "constitution.yaml"
        save_constitution(signed, const_path)
        print(f"2. Created constitution with {len(const.invariants)} invariants")

        # 3. Save public key for manual verification
        import shutil
        public_key_path = out_dir / "public_key.pem"
        shutil.copy2(str(pub_path), str(public_key_path))
        print("3. Saved public key for verification")

        # 4. Simulate governed action
        @sanna_observe(
            constitution_path=str(const_path),
            private_key_path=str(priv_path),
        )
        def demo_agent(query, context):
            return f"Based on the context, the answer is: {context}"

        result = demo_agent(
            query="What is the project status?",
            context="The project is on track for Q1 delivery.",
        )
        print("4. Simulated governed tool call")

        # 5. Show receipt summary
        receipt = result.receipt
        status = receipt.get("coherence_status", "UNKNOWN")
        checks = receipt.get("checks", [])
        passed = sum(1 for c in checks if c.get("passed"))
        total = len(checks)
        print(f"5. Generated receipt: {receipt.get('receipt_id', 'N/A')[:24]}...")
        print(f"   Status: {status} ({passed}/{total} checks passed)")

        # 6. Write receipt to disk
        receipt_path = out_dir / f"receipt-demo-{uuid.uuid4().hex[:8]}.json"
        from .utils.safe_io import atomic_write_text_sync
        atomic_write_text_sync(receipt_path, json.dumps(receipt, indent=2))

        # 7. Verify receipt
        from .verify import load_schema
        schema = load_schema()
        vr = verify_receipt(receipt, schema, public_key_path=str(pub_path),
                           constitution_path=str(const_path))
        icon = "VALID" if vr.valid else "INVALID"
        print(f"6. Verified receipt: {icon}")

    print()
    print(f"Receipt saved to: {receipt_path}")
    print(f"Public key saved to: {public_key_path}")
    print()
    print("Next steps:")
    print(f"  sanna inspect {receipt_path}")
    print(f"  sanna verify {receipt_path} --public-key {public_key_path}")
    return 0


# =============================================================================
# INSPECT CLI
# =============================================================================

def main_inspect():
    """Pretty-print the contents of a Sanna receipt JSON file."""
    parser = argparse.ArgumentParser(
        description="Pretty-print a Sanna receipt"
    )
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument("--json", action="store_true",
                       help="Output raw JSON (formatted)")
    parser.add_argument("--version", action="version", version=f"sanna-inspect {TOOL_VERSION}")
    args = parser.parse_args()

    try:
        with open(args.receipt) as f:
            receipt = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.receipt}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(receipt, indent=2))
        return 0

    # Header
    print("=" * 60)
    print("SANNA RECEIPT")
    print("=" * 60)
    print(f"  Receipt ID:    {receipt.get('receipt_id', 'N/A')}")
    print(f"  Trace ID:      {receipt.get('trace_id', 'N/A')}")
    print(f"  Timestamp:     {receipt.get('timestamp', 'N/A')}")
    print(f"  Tool Version:  {receipt.get('tool_version', 'N/A')}")
    print(f"  Schema:        {receipt.get('schema_version', 'N/A')}")
    print(f"  Fingerprint:   {receipt.get('receipt_fingerprint', 'N/A')[:32]}...")
    print()

    # Status
    status = receipt.get("coherence_status", "UNKNOWN")
    checks = receipt.get("checks", [])
    passed = sum(1 for c in checks if c.get("passed"))
    failed = sum(1 for c in checks if not c.get("passed"))
    print(f"  Status:        {status}")
    print(f"  Checks:        {passed} passed, {failed} failed")
    print()

    # Checks detail
    if checks:
        print("-" * 60)
        print("CHECKS")
        print("-" * 60)
        for check in checks:
            icon = "PASS" if check.get("passed") else "FAIL"
            check_id = check.get("check_id", "?")
            name = check.get("name", "")
            severity = check.get("severity", "")
            print(f"  [{icon}] {check_id}: {name}")
            if severity:
                print(f"         severity: {severity}")
            evidence = check.get("evidence")
            if evidence and not check.get("passed"):
                print(f"         evidence: {evidence}")
        print()

    # Authority decisions
    auth = receipt.get("authority_decisions")
    if auth and isinstance(auth, list) and len(auth) > 0:
        print("-" * 60)
        print("AUTHORITY DECISIONS")
        print("-" * 60)
        for decision in auth:
            d_type = decision.get("decision", "?")
            tool = decision.get("tool_name", decision.get("action", "?"))
            print(f"  {d_type}: {tool}")
        print()

    # Escalation events
    esc = receipt.get("escalation_events")
    if esc and isinstance(esc, list) and len(esc) > 0:
        print("-" * 60)
        print("ESCALATION EVENTS")
        print("-" * 60)
        for event in esc:
            print(f"  {event.get('type', '?')}: {event.get('target', '?')}")
        print()

    # Constitution reference
    const_ref = receipt.get("constitution_ref")
    if const_ref and isinstance(const_ref, dict):
        print("-" * 60)
        print("CONSTITUTION")
        print("-" * 60)
        print(f"  Document ID:   {const_ref.get('document_id', 'N/A')}")
        print(f"  Policy Hash:   {const_ref.get('policy_hash', 'N/A')[:32]}...")
        print(f"  Version:       {const_ref.get('version', 'N/A')}")
        print()

    # Signature
    sig = receipt.get("receipt_signature")
    if sig and isinstance(sig, dict):
        print("-" * 60)
        print("SIGNATURE")
        print("-" * 60)
        print(f"  Key ID:        {sig.get('key_id', 'N/A')}")
        print(f"  Scheme:        {sig.get('scheme', 'N/A')}")
        has_sig = bool(sig.get("value"))
        print(f"  Signed:        {'Yes' if has_sig else 'No'}")
        print()

    # Halt event
    halt = receipt.get("halt_event")
    if halt and isinstance(halt, dict) and halt.get("halted"):
        print("-" * 60)
        print("HALT EVENT")
        print("-" * 60)
        print(f"  Reason:        {halt.get('reason', 'N/A')}")
        print(f"  Failed Checks: {halt.get('failed_checks', [])}")
        print()

    print("=" * 60)
    return 0


# =============================================================================
# CHECK-CONFIG CLI
# =============================================================================

def main_check_config():
    """Dry-run validation of a gateway configuration file."""
    parser = argparse.ArgumentParser(
        description="Validate a Sanna gateway configuration (dry-run)"
    )
    parser.add_argument("config", help="Path to gateway YAML config file")
    parser.add_argument("--version", action="version", version=f"sanna-check-config {TOOL_VERSION}")
    args = parser.parse_args()

    import os
    import stat
    import yaml

    errors = []
    warnings_list = []

    # 1. YAML syntax
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML syntax: {e}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("Error: Config must be a YAML mapping.", file=sys.stderr)
        return 1

    print(f"Config: {config_path}")
    print()
    print("  [PASS] YAML syntax valid")

    # 2. Required fields
    gw = data.get("gateway", {})
    if not gw:
        errors.append("Missing 'gateway' section")
    else:
        const_path = gw.get("constitution")
        if not const_path:
            errors.append("Missing gateway.constitution")
        else:
            # 3. Constitution file exists
            resolved = Path(const_path).expanduser()
            if not resolved.is_absolute():
                resolved = config_path.parent / resolved
            if resolved.exists():
                print(f"  [PASS] Constitution file exists: {resolved}")

                # Check if signed
                try:
                    from .constitution import load_constitution
                    c = load_constitution(str(resolved))
                    if c.policy_hash:
                        sig = c.provenance.signature
                        if sig and sig.value:
                            print(f"  [PASS] Constitution is signed (key_id={sig.key_id})")
                        else:
                            warnings_list.append("Constitution is hashed but NOT Ed25519 signed")
                    else:
                        warnings_list.append("Constitution has no policy_hash (unsigned)")
                except Exception as e:
                    errors.append(f"Constitution load error: {e}")
            else:
                errors.append(f"Constitution file not found: {resolved}")

        # 4. Signing key
        key_path = gw.get("signing_key")
        if key_path:
            resolved_key = Path(key_path).expanduser()
            if not resolved_key.is_absolute():
                resolved_key = config_path.parent / resolved_key
            if resolved_key.exists():
                print(f"  [PASS] Signing key exists: {resolved_key}")
                # Check permissions
                if os.name != "nt":
                    mode = stat.S_IMODE(os.stat(resolved_key).st_mode)
                    if mode == 0o600:
                        print("  [PASS] Key permissions: 0o600")
                    else:
                        warnings_list.append(f"Key permissions are {oct(mode)}, expected 0o600")
            else:
                errors.append(f"Signing key not found: {resolved_key}")
        else:
            warnings_list.append("No signing_key configured (receipts will be unsigned)")

    # 5. Downstream servers
    downstreams = data.get("downstream", [])
    if not downstreams:
        errors.append("No 'downstream' servers configured")
    else:
        for i, ds in enumerate(downstreams):
            name = ds.get("name", f"server-{i}")
            cmd = ds.get("command")
            if not cmd:
                errors.append(f"Downstream '{name}' has no command")
            else:
                print(f"  [PASS] Downstream '{name}': {cmd}")

    # Summary
    print()
    if warnings_list:
        print("Warnings:")
        for w in warnings_list:
            print(f"  [WARN] {w}")

    if errors:
        print("Errors:")
        for e in errors:
            print(f"  [FAIL] {e}")
        print()
        print(f"Result: INVALID ({len(errors)} errors)")
        return 1

    print(f"Result: VALID")
    return 0


# =============================================================================
# UNIFIED CLI
# =============================================================================

def main_sanna():
    """Unified entry point: ``sanna <subcommand> [args]``."""
    subcommands = {
        "init": ("sanna.init_constitution:main", "Interactive constitution generator"),
        "keygen": ("sanna.cli:main_keygen", "Generate Ed25519 keypair"),
        "sign": ("sanna.cli:main_sign_constitution", "Sign a constitution"),
        "verify": ("sanna.cli:main_verify", "Verify a receipt"),
        "verify-constitution": ("sanna.cli:main_verify_constitution", "Verify a constitution"),
        "approve": ("sanna.cli:approve_constitution_cmd", "Approve a constitution"),
        "diff": ("sanna.cli:diff_cmd", "Diff two constitutions"),
        "demo": ("sanna.cli:main_demo", "Run self-contained governance demo"),
        "inspect": ("sanna.cli:main_inspect", "Pretty-print a receipt"),
        "check-config": ("sanna.cli:main_check_config", "Validate gateway config (dry-run)"),
        "gateway": ("sanna.gateway:main", "Start MCP enforcement proxy"),
        "mcp": ("sanna.mcp.__main__:main", "Start MCP server"),
        "drift-report": ("sanna.cli:main_drift_report", "Fleet governance drift report"),
        "bundle-create": ("sanna.cli:main_create_bundle", "Create evidence bundle"),
        "bundle-verify": ("sanna.cli:main_verify_bundle", "Verify evidence bundle"),
        "generate": ("sanna.cli:main_generate", "Generate receipt from trace-data JSON"),
    }

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(f"sanna v{TOOL_VERSION} — Trust infrastructure for AI agents")
        print()
        print("Usage: sanna <command> [options]")
        print()
        print("Commands:")
        max_name = max(len(n) for n in subcommands)
        for name, (_, desc) in subcommands.items():
            print(f"  {name:<{max_name + 2}} {desc}")
        print()
        print("Run 'sanna <command> --help' for command-specific options.")
        return 0

    if sys.argv[1] == "--version":
        print(f"sanna {TOOL_VERSION}")
        return 0

    cmd = sys.argv[1]
    if cmd not in subcommands:
        print(f"Error: Unknown command '{cmd}'.", file=sys.stderr)
        print(f"Run 'sanna --help' for available commands.", file=sys.stderr)
        return 1

    # Rewrite sys.argv so the subcommand sees itself as the program
    sys.argv = [f"sanna {cmd}"] + sys.argv[2:]

    # Dispatch to the subcommand function
    module_path, _ = subcommands[cmd]
    mod_name, func_name = module_path.rsplit(":", 1)

    import importlib
    mod = importlib.import_module(mod_name)
    func = getattr(mod, func_name)
    result = func()
    return result if result is not None else 0


# Legacy aliases
main_receipt = main_generate


if __name__ == "__main__":
    sys.exit(main_generate())
