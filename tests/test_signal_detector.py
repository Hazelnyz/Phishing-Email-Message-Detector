from src.signal_detector import detect_signals, analyze_urls, check_sender_mismatch


def test_detects_urgency_signal():
    result = detect_signals("You must act immediately within 2 hours or lose access.")
    cats = [s["category"] for s in result["signals"]]
    assert "Urgency / Time Pressure" in cats


def test_detects_threat_signal():
    result = detect_signals("Your account will be suspended and permanently locked.")
    cats = [s["category"] for s in result["signals"]]
    assert "Threats / Negative Consequences" in cats


def test_detects_credential_request():
    result = detect_signals("Please reply with your password to verify your identity.")
    cats = [s["category"] for s in result["signals"]]
    assert "Credential / OTP Request" in cats


def test_detects_payment_request():
    result = detect_signals("Please transfer Rs. 5000 to claim your scholarship refund.")
    cats = [s["category"] for s in result["signals"]]
    assert "Suspicious Payment / Financial Request" in cats


def test_clean_message_has_no_signals():
    result = detect_signals("Hey, are we still meeting for lunch today?")
    assert result["signals"] == []
    assert result["total_weight"] == 0


def test_url_shortener_flagged_as_suspicious():
    findings = analyze_urls("Click here: http://bit.ly/abc123")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert any("shortener" in issue for issue in findings[0]["issues"])


def test_suspicious_tld_flagged():
    findings = analyze_urls("Verify at http://vit-alert.xyz/login")
    assert findings[0]["severity"] == "high"
    assert any("top-level domain" in issue for issue in findings[0]["issues"])


def test_https_url_with_no_issues_on_trusted_domain():
    findings = analyze_urls("Visit https://vit.ac.in/portal for details.")
    assert findings[0]["issues"] == []


def test_ip_based_url_flagged():
    findings = analyze_urls("Login at http://192.168.1.50/login")
    assert any("IP address" in issue for issue in findings[0]["issues"])


def test_lookalike_domain_flagged():
    findings = analyze_urls("Verify now at http://vit.ac.in.login-secure.com/verify")
    assert findings[0]["severity"] == "high"


def test_urls_are_never_fetched(monkeypatch):
    """Guarantees analyze_urls never performs real network I/O."""
    import socket

    def fail_on_network(*args, **kwargs):
        raise AssertionError("Network access attempted during URL analysis!")

    monkeypatch.setattr(socket, "create_connection", fail_on_network)
    # Should not raise, since no real connection should ever be attempted.
    analyze_urls("Click http://totally-fake-domain-for-testing.com/path")


def test_sender_mismatch_detected_for_untrusted_domain():
    result = check_sender_mismatch("support@vit-portal-verify.com")
    assert result["mismatch"] is True


def test_sender_trusted_domain_not_flagged():
    result = check_sender_mismatch("dean@vit.ac.in")
    assert result["mismatch"] is False


def test_sender_none_returns_none():
    assert check_sender_mismatch(None) is None


def test_multiple_signals_combine_weight():
    result = detect_signals(
        "URGENT: verify your password immediately at http://bit.ly/x or your account will be suspended."
    )
    assert len(result["signals"]) >= 3
    assert result["total_weight"] > 50
