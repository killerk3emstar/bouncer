"""PiiControl: validated entities, overlap handling, clearance downgrade, false positives."""

from __future__ import annotations

import base64

import pytest

from bouncer.controls.pii import PiiControl, card_brand, iban_valid, luhn_valid, nip_valid, pesel_valid
from bouncer.core import Action
from bouncer.policy.schema import PiiCfg

from ._util import ctx, redact, run


def _pii(text: str, role: str = "user", context=None, control=None):
    clean, findings = run(text, role, control or "pii", context=context)
    return clean, [f for f in findings if f.control == "pii"]


def _ents(text: str, **kw) -> list[str]:
    return [f.rule for f in _pii(text, **kw)[1]]


def test_validators():
    assert pesel_valid("44051401359") and not pesel_valid("44051401358")
    assert pesel_valid("02270803624")  # born 2002 (month + 20)
    assert not pesel_valid("44133101354")  # month 13 does not exist
    assert nip_valid("1234563218") and not nip_valid("1234563219")
    assert iban_valid("PL61109010140000071219812874") and not iban_valid("PL61109010140000071219812875")
    assert iban_valid("DE89 3704 0044 0532 0130 00") and iban_valid("GB29NWBK60161331926819")
    assert iban_valid("FR1420041010050500013M02606") and iban_valid("NL91ABNA0417164300")
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    assert card_brand("4111111111111111") == "Visa" and card_brand("378282246310005") == "Amex"
    assert card_brand("5500000000000004") == "Mastercard" and card_brand("9999999999999995") is None


@pytest.mark.parametrize(
    "text,entity,value,action",
    [
        ("Contact jan.kowalski@bank.example about the claim", "EMAIL", "jan.kowalski@bank.example", Action.REDACT),
        ("Call me at +48 600 123 456 tomorrow", "PHONE", "+48 600 123 456", Action.REDACT),
        ("tel. 600-123-456", "PHONE", "600-123-456", Action.REDACT),
        ("komórka: 600123456", "PHONE", "600123456", Action.REDACT),
        ("US office (555) 123-4567", "PHONE", "(555) 123-4567", Action.REDACT),
        ("Call me at 600 123 456 after 5", "PHONE", "600 123 456", Action.REDACT),
        ("m\u00f3j numer to 600-123-456", "PHONE", "600-123-456", Action.REDACT),
        ("Zadzwo\u0144 na 22 123 45 67", "PHONE", "22 123 45 67", Action.REDACT),
        ("order ref ok, mobile: 600 123 456", "PHONE", "600 123 456", Action.REDACT),
        ("600 123 456 (mobile)", "PHONE", "600 123 456", Action.REDACT),
        ("London +44 20 7946 0958", "PHONE", "+44 20 7946 0958", Action.REDACT),
        ("Client PESEL 44051401359, please verify", "PESEL", "44051401359", Action.REDACT),
        ("NIP 123-456-32-18", "NIP", "123-456-32-18", Action.LOG),
        ("NIP: 1234563218", "NIP", "1234563218", Action.LOG),
        ("VAT PL1234563218 on the invoice", "NIP", "PL1234563218", Action.LOG),
        ("Account PL61 1090 1014 0000 0712 1981 2874 please", "IBAN", "PL61 1090 1014 0000 0712 1981 2874", Action.REDACT),
        ("IBAN PL61109010140000071219812874", "IBAN", "PL61109010140000071219812874", Action.REDACT),
        ("Konto 61 1090 1014 0000 0712 1981 2874", "IBAN", "61 1090 1014 0000 0712 1981 2874", Action.REDACT),
        ("Pay to DE89 3704 0044 0532 0130 00", "IBAN", "DE89 3704 0044 0532 0130 00", Action.REDACT),
        ("Card 4111-1111-1111-1111 exp 12/27", "CREDIT_CARD", "4111-1111-1111-1111", Action.BLOCK),
        ("Card 4111 1111 1111 1111", "CREDIT_CARD", "4111 1111 1111 1111", Action.BLOCK),
        ("Card 4111-1111 1111-1111", "CREDIT_CARD", "4111-1111 1111-1111", Action.BLOCK),
        ("Amex 3782 822463 10005", "CREDIT_CARD", "3782 822463 10005", Action.BLOCK),
        ("mc 5500000000000004", "CREDIT_CARD", "5500000000000004", Action.BLOCK),
    ],
)
def test_detects_entity(text, entity, value, action):
    clean, findings = _pii(text)
    f = next((f for f in findings if f.rule == entity), None)
    assert f is not None, [x.rule for x in findings]
    assert clean[f.span[0] : f.span[1]] == value
    assert f.action == action
    assert f.id == f"pii.{entity}"
    assert value not in (f.evidence or "") and value not in f.message
    if action == Action.REDACT:
        assert value not in redact(clean, findings) and f"[REDACTED:{entity}]" in redact(clean, findings)


@pytest.mark.parametrize(
    "text",
    [
        "PESEL 44051401358 has a wrong checksum",  # wrong checksum: just a number
        "Invoice number 1234563218",  # NIP checksum but no context or format
        "Order 600123456 shipped yesterday",  # bare 9 digits without phone context
        "Kwota 123 456 789 zł do zapłaty",  # amount with spaces
        "Revenue was 123 456 789 PLN in Q3",
        "Meeting on 2024-10-03 at 10:30, ticket 1234-5678",
        "Card 4111111111111112 fails Luhn",
        "Reference 9999999999999995",  # Luhn valid, unknown issuer
        "icon@2x.png and git@github.com:org/repo.git",
        "Version 1.2.3.4 and IP 192.168.100.200",
        "timestamp 1696345678901",
        "PL61109010140000071219812875 is not valid",
        "Ratio 0.600123456 and total 600,123,456.00",
        "customer order number is 600 123 456, please check the status",
        "Numer zam\u00f3wienia 600-123-456 nie dotar\u0142",
        "Batch 601 222 333 was reconciled",
        "Call about order 600 123 456",
        "invoice 555-123-4567 is overdue",
        "ticket (22) 123 45 67 closed",
    ],
)
def test_no_false_positives(text):
    assert _ents(text) == []


def test_overlap_prefers_iban_over_phone_and_card():
    assert _ents("Konto: PL61 1090 1014 0000 0712 1981 2874") == ["IBAN"]


def test_multiple_entities_each_reported():
    ents = _ents("Jan, jan@bank.example, +48 600 123 456, PESEL 44051401359, card 4111 1111 1111 1111")
    assert sorted(ents) == ["CREDIT_CARD", "EMAIL", "PESEL", "PHONE"]


def test_clearance_downgrades_redact_to_log_for_output_only():
    text = "Customer jan@bank.example, PESEL 44051401359, card 4111 1111 1111 1111"
    _, out_conf = _pii(text, role="assistant", context=ctx("confidential"))
    actions = {f.rule: f.action for f in out_conf}
    assert actions["EMAIL"] == Action.LOG and actions["PESEL"] == Action.LOG
    assert actions["CREDIT_CARD"] == Action.BLOCK  # block stays block
    assert "clearance" in next(f for f in out_conf if f.rule == "EMAIL").message
    _, in_conf = _pii(text, role="user", context=ctx("confidential"))
    assert {f.rule: f.action for f in in_conf}["EMAIL"] == Action.REDACT
    _, out_internal = _pii(text, role="assistant", context=ctx("internal"))
    assert {f.rule: f.action for f in out_internal}["EMAIL"] == Action.REDACT
    _, tool_conf = _pii(text, role="tool_result", context=ctx("restricted"))
    assert {f.rule: f.action for f in tool_conf}["EMAIL"] == Action.LOG


def test_entities_not_listed_are_ignored():
    c = PiiControl(PiiCfg(entities={"EMAIL": "redact"}))
    assert [f.rule for f in _pii("jan@bank.example PESEL 44051401359", control=c)[1]] == ["EMAIL"]


def test_policy_change_email_block():
    c = PiiControl(PiiCfg(entities={"EMAIL": "block"}))
    f = _pii("write to jan@bank.example", control=c)[1][0]
    assert f.action == Action.BLOCK and "blocked" in f.message


def test_base64_encoded_pii_redacts_blob():
    blob = base64.b64encode(b"customer list: jan.kowalski@bank.example, anna.nowak@bank.example").decode()
    clean, findings = _pii(f"export {blob}")
    assert {f.rule for f in findings} == {"EMAIL"}
    assert all(clean[f.span[0] : f.span[1]] == blob for f in findings)


def test_fullwidth_digits_card():
    text = "card ４１１１ １１１１ １１１１ １１１１"
    assert _ents(text) == ["CREDIT_CARD"]


def test_evidence_is_masked():
    _, findings = _pii("jan.kowalski@bank.example 4111 1111 1111 1111 PESEL 44051401359")
    ev = {f.rule: f.evidence for f in findings}
    assert ev["EMAIL"] == "j***@bank.example"
    assert ev["CREDIT_CARD"] == "************1111"
    assert ev["PESEL"] == "44*******59"
