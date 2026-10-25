import pytest
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.mark.parametrize("route", ["/", "/analyze", "/performance", "/awareness"])
def test_pages_load_successfully(client, route):
    resp = client.get(route)
    assert resp.status_code == 200


def test_404_returns_custom_error_page(client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404


def test_removed_about_page_returns_404(client):
    assert client.get("/about").status_code == 404


def test_analyze_post_with_message_returns_result(client):
    resp = client.post("/analyze", data={"message": "Please send your password immediately or be suspended."})
    assert resp.status_code == 200
    assert b"Risk Level" in resp.data


def test_analyze_post_without_message_shows_error(client):
    resp = client.post("/analyze", data={"message": ""})
    assert resp.status_code == 200
    assert b"Please enter a message" in resp.data


def test_api_analyze_requires_message(client):
    resp = client.post("/api/analyze", json={})
    assert resp.status_code == 400


def test_api_analyze_returns_json_result(client):
    resp = client.post("/api/analyze", json={"message": "Click here urgently to verify your account!"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "risk_level" in data
    assert "risk_score" in data


def test_api_defangs_urls_and_never_returns_clickable_link(client):
    response = client.post("/api/analyze", json={"message": "Review this link http://bit.ly/verify urgently"})
    assert response.status_code == 200
    finding = response.get_json()["url_findings"][0]
    assert finding["url"].startswith("hxxp://")
    assert "[.]" in finding["url"]


def test_message_is_escaped_in_rendered_html(client):
    """Ensures user input is HTML-escaped (Jinja2 autoescaping / no XSS)."""
    payload = "<script>alert('xss')</script>"
    resp = client.post("/analyze", data={"message": payload})
    assert b"<script>alert" not in resp.data
    assert b"&lt;script&gt;" in resp.data


def test_oversized_message_is_rejected(client):
    huge_message = "a" * 6000
    resp = client.post("/analyze", data={"message": huge_message})
    assert resp.status_code == 200
    assert b"too long" in resp.data


def test_metric_templates_do_not_hard_code_metric_values():
    from pathlib import Path
    import re
    root = Path(__file__).resolve().parents[1]
    metric_templates = [root / "templates" / "home.html", root / "templates" / "performance.html"]
    for path in metric_templates:
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"(?<![\w{])\d+(?:\.\d+)?\s*%", source), f"Hard-coded percentage in {path.name}"
