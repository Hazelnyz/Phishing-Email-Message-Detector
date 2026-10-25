import pytest
from src.risk_engine import classify_risk, ml_predict


def test_clearly_phishing_message_is_high_risk():
    msg = ("URGENT: Your VIT account will be suspended in 2 hours. Reply with "
           "your password immediately at http://vit-secure-verify.xyz/login")
    result = classify_risk(msg, sender="support@vit-secure-verify.xyz")
    assert result["risk_level"] == "HIGH RISK"
    assert result["risk_score"] >= 65


def test_clearly_legit_message_is_low_risk():
    msg = "Hey, are we still meeting for the group project discussion at 5 PM today?"
    result = classify_risk(msg)
    assert result["risk_level"] == "LOW RISK"
    assert result["risk_score"] < 35


def test_short_message_is_insufficient_information():
    result = classify_risk("hi")
    assert result["risk_level"] == "INSUFFICIENT INFORMATION"
    assert result["risk_score"] == 0


def test_empty_message_is_insufficient_information():
    result = classify_risk("")
    assert result["risk_level"] == "INSUFFICIENT INFORMATION"


def test_result_contains_explanation_and_recommendations():
    result = classify_risk("Please send your OTP immediately to verify your account.")
    assert isinstance(result["explanation"], str) and len(result["explanation"]) > 0
    assert isinstance(result["recommendations"], list) and len(result["recommendations"]) > 0


def test_low_risk_explanation_includes_no_guarantee_disclaimer():
    result = classify_risk("Thanks for sending the notes, really appreciate it!")
    if result["risk_level"] == "LOW RISK":
        assert "not a guarantee" in result["explanation"].lower() or \
               "not a guarantee" in " ".join(result["recommendations"]).lower()


def test_ml_predict_returns_valid_label():
    result = ml_predict("Your semester fee payment failed, resend urgently.")
    assert result["prediction"] in ("phishing", "legitimate")


def test_risk_score_bounded_0_to_100():
    msgs = [
        "URGENT verify your password now at http://bit.ly/x or account suspended, pay Rs 5000 now",
        "Hi, lunch at 1?",
        "",
        "The library closes at 10 PM during exams.",
    ]
    for m in msgs:
        result = classify_risk(m)
        assert 0 <= result["risk_score"] <= 100


@pytest.mark.parametrize("message", [
    "gimme ur credit details", "pls send me your credit card details",
    "share your debit card number", "send ur cvv", "give me the card expiry",
    "pls send your card pin", "gimme ur bank acct details", "share your UPI info",
    "send me the IFSC no.", "give me net banking login info", "send your Aadhaar number",
    "share ur PAN details", "gimme passport no", "send your date of birth",
    "pls share registration number", "send me the otp", "give me your pwd",
])
def test_sensitive_information_requests_never_low(message):
    assert classify_risk(message)["risk_level"] in {"MEDIUM RISK", "HIGH RISK"}


@pytest.mark.parametrize("message", [
    "send me the notes pls", "share your timetable", "can u give me the lab record",
    "gimme the lecture slides", "pls send the assignment", "share ur class notes",
    "can u send me the pdf", "give me the room number", "pls share the meeting link",
    "send me the lab manual", "can you share the schedule", "gimme the book name",
    "pls send the photo", "share your project outline", "can u give me directions",
])
def test_informal_legitimate_requests_not_high(message):
    assert classify_risk(message)["risk_level"] != "HIGH RISK"


def test_very_short_unsignalled_message_is_insufficient():
    assert classify_risk("hello there friend")["risk_level"] == "INSUFFICIENT INFORMATION"


def test_requested_live_examples_have_required_risk_labels():
    examples = [
        "gimme ur credit details",
        "send ur card no and cvv to confirm",
        "Please submit the assignment by tonight",
        "Dear student, fee payment last date is 30 Oct, pay via the official portal",
        "Your VIT account will be suspended in 24 hours. Click http://vit-verify.xyz/login now.",
    ]
    levels = [classify_risk(message)["risk_level"] for message in examples]
    assert levels[0] != "LOW RISK"
    assert levels[1] != "LOW RISK"
    assert levels[2] != "HIGH RISK"
    assert levels[3] in {"LOW RISK", "MEDIUM RISK"}
    assert levels[4] == "HIGH RISK"


@pytest.mark.parametrize("message", [
    "gimme ur credit details",
    "Please pay the fee via the official portal today",
    "View the notice at http://vit-verify.xyz/login",
])
def test_high_severity_signal_floor_overrides_low_ml_score(monkeypatch, message):
    import src.risk_engine as engine
    monkeypatch.setattr(engine, "ml_predict", lambda _: {
        "prediction": "legitimate", "probabilities": {"legitimate": 0.99, "phishing": 0.01},
        "model_name": "test model",
    })
    assert engine.classify_risk(message)["risk_level"] == "MEDIUM RISK"
