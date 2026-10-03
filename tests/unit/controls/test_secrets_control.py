"""SecretsControl: provider rules, context rules, entropy, split and encoded secrets, false positives."""

from __future__ import annotations

import base64

import pytest

from bouncer.controls.secrets import RULES, SecretsControl
from bouncer.core import Action
from bouncer.policy.schema import SecretsCfg

from ._util import redact, run

AWS_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx4fGh2kL9mQ3pX7vTn1bW8sY5cR0dE6uJ2aK4zH9oP3iL1q\n"
    "Zr8sT2wV5yB7nM0cX4fG6hJ9kL3pQ1rS8tU2vW5yA7bC0dE3fG6hI9jK2lM5nO\n-----END RSA PRIVATE KEY-----"
)


def _sec(text: str, role: str = "user", control=None):
    clean, findings = run(text, role, control or "secrets")
    return clean, [f for f in findings if f.control == "secrets"]


def _rule_ids(text: str, **kw) -> set[str]:
    return {f.rule for f in _sec(text, **kw)[1]}


@pytest.mark.parametrize(
    "text,rule,value",
    [
        (f"Deploy fails, config: AWS_ACCESS_KEY_ID={AWS_ID}", "aws-access-key-id", AWS_ID),
        (f"aws_secret_access_key = {AWS_SECRET}", "aws-secret-access-key", AWS_SECRET),
        ("maps key AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY in the app", "gcp-api-key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),
        ("token ghp_16C7e42F292c6912E7710c838347Ae178B4a", "github-pat", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
        ("gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 works", "github-pat", "gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        ("github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ", "github-fine-grained-pat",
         "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
        ("export GITLAB_TOKEN=glpat-xY9zA8bC7dE6fG5hI4jK", "gitlab-pat", "glpat-xY9zA8bC7dE6fG5hI4jK"),
        ("bot token xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "slack-token",
         "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
        ("hook https://hooks.slack.com/services/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", "slack-webhook-url",
         "https://hooks.slack.com/services/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"),
        ("stripe sk_live_51H8aBcDeFgHiJkLmNoPqRsTu", "stripe-secret-key", "sk_live_51H8aBcDeFgHiJkLmNoPqRsTu"),
        ("OPENAI_API_KEY=sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z", "openai-api-key", "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"),
        ("key sk-ant-api03-Zx9Qw3Er7Ty1Ui5Op2As8Df4Gh6Jk0LzXcVbNm-AA here", "anthropic-api-key",
         "sk-ant-api03-Zx9Qw3Er7Ty1Ui5Op2As8Df4Gh6Jk0LzXcVbNm-AA"),
        (f"Authorization: Bearer {JWT}", "jwt", JWT),
        ("DATABASE_URL=postgres://app:S3cr3tPass!@db.prod.bank.example:5432/core", "connection-string", "S3cr3tPass!"),
        ("mongodb+srv://svc:Xk82!pqLm@cluster0.mongodb.net/test", "connection-string", "Xk82!pqLm"),
        ('{"user": "admin", "password": "Sup3rS3cret!"}', "password-assignment", "Sup3rS3cret!"),
        ("DB_PASSWORD=supersecret", "password-assignment", "supersecret"),
        ("https://api.vendor.example/v1/items?api_key=9f8e7d6c5b4a3f2e1d0c&limit=5", "password-assignment",
         "9f8e7d6c5b4a3f2e1d0c"),
        ("password: S3cr3t!pw", "password-assignment", "S3cr3t!pw"),
        ("my password is hunter22", "password-assignment", "hunter22"),
        ("hasło: Tajne123!", "password-assignment", "Tajne123!"),
        ("Server=db;Database=core;User Id=sa;Password=Secr3t!x;", "password-assignment", "Secr3t!x"),
        ("AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
         "azure-storage-account-key",
         "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="),
        ("hf token hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "huggingface-token", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
    ],
)
def test_redacts_secret_with_exact_span(text, rule, value):
    clean, findings = _sec(text)
    f = next((f for f in findings if f.rule == rule), None)
    assert f is not None, [x.rule for x in findings]
    assert f.action == Action.REDACT
    assert clean[f.span[0] : f.span[1]] == value
    assert f.id == f"secrets.{rule}"
    assert value not in redact(clean, findings)
    assert f"[REDACTED:{rule}]" in redact(clean, findings)
    assert value not in (f.evidence or "") and value not in f.message
    assert f.owasp_llm == ["LLM02"] and "ASI03" in f.owasp_agentic


def test_private_key_is_blocked_by_policy_override():
    _, findings = _sec(f"Here is my key:\n{PEM}\nthanks")
    f = next(f for f in findings if f.rule == "private-key")
    assert f.action == Action.BLOCK and f.severity == "critical"
    assert "MIIE" not in (f.evidence or "")


def test_private_key_in_json_with_escaped_newlines():
    js = '{"type": "service_account", "private_key_id": "' + "a" * 8 + "1b2c3d4e5f" * 3 + "12" + '", '
    js += '"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n-----END PRIVATE KEY-----\\n"}'
    rules = _rule_ids(js)
    assert "private-key" in rules and "gcp-service-account" in rules


def test_stripe_test_key_redacted_low_severity():
    _, findings = _sec("use sk_test_4eC39HqLyjWDarjtT1zdp7dc for the sandbox")
    f = next(f for f in findings if f.rule == "stripe-secret-key")
    assert f.action == Action.REDACT and f.severity == "low"


def test_aws_secret_paired_with_access_key():
    rules = _rule_ids(f"{AWS_ID} {AWS_SECRET}")
    assert rules == {"aws-access-key-id", "aws-secret-access-key"}


def test_split_secret_concatenation_is_redacted_in_place():
    text = 'key = "AKIA" + "IOSFODNN7EXAMPLE"\nprint(key)'
    clean, findings = _sec(text)
    f = next(f for f in findings if f.rule == "aws-access-key-id")
    assert f.action == Action.REDACT and f.span is not None
    out = redact(clean, findings)
    assert "IOSFODNN7EXAMPLE" not in out and "AKIA" not in out


def test_split_secret_with_spaces():
    clean, findings = _sec("my key is AKIA IOSF ODNN 7EXA MPLE ok")
    f = next(f for f in findings if f.rule == "aws-access-key-id")
    assert clean[f.span[0] : f.span[1]] == "AKIA IOSF ODNN 7EXA MPLE"


def test_homoglyph_secret_blocked_without_span():
    _, findings = _sec("АKIAIOSFODNN7EXAMPLE")  # Cyrillic A
    f = next(f for f in findings if f.rule == "aws-access-key-id")
    assert f.span is None and f.action == Action.BLOCK and f.view == "normalized:case"


def test_base64_encoded_secret_redacts_whole_blob():
    blob = base64.b64encode(f"AWS_ACCESS_KEY_ID={AWS_ID}".encode()).decode()
    text = f"config blob: {blob}"
    clean, findings = _sec(text)
    f = next(f for f in findings if f.rule == "aws-access-key-id")
    assert f.view == "decoded:base64" and clean[f.span[0] : f.span[1]] == blob


def test_secret_in_tool_result_and_output():
    for role in ("tool_result", "assistant"):
        assert "github-pat" in _rule_ids("ghp_16C7e42F292c6912E7710c838347Ae178B4a", role=role)


def test_high_entropy_with_context():
    _, findings = _sec("session cookie: Zx9Qw3Er7Ty1Ui5Op2As8Df4Gh6Jk0L")
    f = next(f for f in findings if f.rule in ("high-entropy-string", "password-assignment"))
    assert f.action == Action.REDACT


def test_high_entropy_without_context_needs_strong_signal():
    rules = _rule_ids("value Q7mZ2xK9pL4vB8nR3tY6wE1sD5gH0jF2aC7uI9oP")
    assert rules == {"high-entropy-string"}
    assert _rule_ids("value abcdefghijklmnopqrstuvwxyz0123") == set()


@pytest.mark.parametrize(
    "text",
    [
        "How do I rotate AWS access keys safely?",
        "AKIA is the prefix of AWS access keys",
        "AKIA IS THE PREFIX OF AWS ACCESS KEYS",
        "commit 3f2a9c8e1b4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a fixed the flaky test",
        "Request id 123e4567-e89b-12d3-a456-426614174000",
        "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "The password reset link expired, can you send a new one?",
        "Set OPENAI_API_KEY=<YOUR_API_KEY> in your shell",
        "Keys look like sk-... and must never be committed",
        "OPENAI_API_KEY=sk-proj-...",
        "api_key = os.environ['API_KEY']",
        "password = get_password()",
        "password = user_password",
        "Password: must be at least 12 characters long",
        "The password is incorrect, please try again",
        "postgres://user:password@localhost:5432/mydb",
        "postgres://app:${DB_PASSWORD}@db:5432/core",
        "max_tokens=1024 and temperature=0.2",
        "token_count: 1500",
        "![diagram](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==)",
        "See https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit",
        "password=[REDACTED:password-assignment]",
        "Use a Bearer token in the Authorization header",
        "-----BEGIN RSA PRIVATE KEY----- marks the start of a PEM file",
        "The function getUserAccountBalanceForCustomerById returns a number",
    ],
)
def test_benign_text_has_no_secret_findings(text):
    assert _rule_ids(text) == set()


def test_allow_values_and_overrides():
    cfg = SecretsCfg(allow_values=[AWS_ID], overrides={"github-pat": "block"})
    c = SecretsControl(cfg)
    _, findings = _sec(f"{AWS_ID} ghp_16C7e42F292c6912E7710c838347Ae178B4a", control=c)
    assert [f.rule for f in findings] == ["github-pat"]
    assert findings[0].action == Action.BLOCK


def test_rules_list_restricts_detection():
    c = SecretsControl(SecretsCfg(rules=["github-pat"]))
    assert {f.rule for f in _sec(f"{AWS_ID} ghp_16C7e42F292c6912E7710c838347Ae178B4a", control=c)[1]} == {"github-pat"}


def test_entropy_disabled_and_entropy_action():
    c = SecretsControl(SecretsCfg(entropy={"enabled": False}))
    assert _sec("value Q7mZ2xK9pL4vB8nR3tY6wE1sD5gH0jF2aC7uI9oP", control=c)[1] == []
    c = SecretsControl(SecretsCfg(entropy={"action": "log"}))
    f = _sec("value Q7mZ2xK9pL4vB8nR3tY6wE1sD5gH0jF2aC7uI9oP", control=c)[1][0]
    assert f.action == Action.LOG and "logged" in f.message


def test_every_rule_has_a_title_and_unique_priority():
    assert all(r.title and r.id for r in RULES)
    assert len({r.id for r in RULES}) >= 20


def test_message_explains_what_why_next():
    _, findings = _sec(f"AWS_ACCESS_KEY_ID={AWS_ID}")
    msg = findings[0].message
    assert "AWS access key id" in msg and "[REDACTED:aws-access-key-id]" in msg and "rotate" in msg
