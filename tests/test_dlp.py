"""Unit tests for the data-exfiltration scanner."""

from agentops.dlp.scanner import CRITICAL, scan_payload


def test_detects_aws_access_key():
    result = scan_payload({"note": "key is AKIAIOSFODNN7EXAMPLE for prod"})
    names = {f.detector for f in result.findings}
    assert "aws_access_key_id" in names
    assert result.max_severity == CRITICAL
    assert result.blocking is True


def test_detects_valid_credit_card_via_luhn():
    result = scan_payload("charge 4111 1111 1111 1111 now")
    assert any(f.detector == "credit_card" for f in result.findings)


def test_ignores_invalid_credit_card():
    # 16 digits that fail the Luhn checksum should not be reported as a card.
    result = scan_payload("order number 1234 5678 9012 3457")
    assert not any(f.detector == "credit_card" for f in result.findings)


def test_detects_ssn_and_private_key():
    result = scan_payload(
        {"ssn": "452-11-9832", "pem": "-----BEGIN RSA PRIVATE KEY-----\nabc"}
    )
    names = {f.detector for f in result.findings}
    assert "us_ssn" in names
    assert "private_key_block" in names


def test_redaction_removes_secret_from_preview():
    result = scan_payload({"token": "AKIAIOSFODNN7EXAMPLE"})
    assert "AKIAIOSFODNN7EXAMPLE" not in str(result.redacted)
    assert "REDACTED" in str(result.redacted)


def test_high_entropy_token_flagged():
    result = scan_payload({"opaque": "f7Kd93Jd82hsAizPq9weR12mVnB4xLoQ"})
    assert any(f.detector in {"high_entropy_token", "generic_secret_assignment"} for f in result.findings)


def test_clean_payload_has_no_findings():
    result = scan_payload({"message": "hello world, please restart the service"})
    assert result.has_findings is False
    assert result.blocking is False


def test_email_is_medium_not_blocking():
    result = scan_payload("contact me at jane@example.com")
    assert any(f.detector == "email_address" for f in result.findings)
    assert result.blocking is False  # medium/low alone never blocks egress


def test_many_small_matches_scan_in_linear_time():
    # A payload full of tiny matches must not blow up (redaction is O(n), not O(n*m)).
    import time

    payload = "x@y.co " * 30000
    start = time.perf_counter()
    result = scan_payload(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.5, f"DLP scan took {elapsed:.2f}s — possible O(n*m) redaction"
    assert any(f.detector == "email_address" for f in result.findings)
