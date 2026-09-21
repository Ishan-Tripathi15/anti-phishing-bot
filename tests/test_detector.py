from detector import analyze_url, analyze_email

def test_ip_url():
    r=analyze_url("http://192.168.1.50/login")
    assert r["risk_score"]>=40
    assert any("IP address" in x for x in r["signals"])

def test_safe_url():
    r=analyze_url("https://example.com/")
    assert r["risk_score"]<40

def test_credential_email():
    r=analyze_email("Urgent: verify your account","Click here immediately and enter your password and OTP.")
    assert r["risk_score"]>=40
    assert any("credentials" in x.lower() for x in r["signals"])
