"""Fake data is deterministic and its identifiers pass their checksums."""

from __future__ import annotations

from demo import data


def test_customer_count_and_determinism():
    first = data.get_customers()
    assert len(first) == data.CUSTOMER_COUNT == 50
    # cached, so identical object; values are stable across a fresh generation too
    assert data.get_customers() is first
    ids = [c.id for c in first]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_unique_pii():
    customers = data.get_customers()
    assert len({c.email for c in customers}) == len(customers)
    assert len({c.pesel for c in customers}) == len(customers)
    assert len({c.iban for c in customers}) == len(customers)


def test_pesel_checksums_valid():
    for c in data.get_customers():
        assert data.pesel_is_valid(c.pesel), c.pesel


def test_iban_checksums_valid():
    for c in data.get_customers():
        assert data.iban_is_valid(c.iban), c.iban
    assert data.iban_is_valid(data.OPS_ACCOUNT_IBAN)


def test_pesel_detects_bad_checksum():
    good = data.get_customers()[0].pesel
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not data.pesel_is_valid(bad)


def test_iban_detects_bad_checksum():
    good = data.get_customers()[0].iban
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    assert not data.iban_is_valid(bad)


def test_test_cards_are_luhn_valid():
    for number in data.TEST_CARDS.values():
        assert data.luhn_is_valid(number), number


def test_emails_and_ibans_look_fake():
    for c in data.get_customers():
        assert c.email.endswith(".example")
        assert "@bank.example" not in c.email  # personal domains, external to the bank
        assert c.iban.startswith("PL" ) and data.SORT_CODE in c.iban


def test_kb_articles():
    kb = data.get_kb()
    assert len(kb) >= 15
    ids = [a.id for a in kb]
    assert len(set(ids)) == len(ids)
    assert {a.classification for a in kb} <= {"public", "internal", "confidential", "restricted"}
    # the security/KYC procedures the scenarios rely on exist
    titles = " ".join(a.title.lower() for a in kb)
    for needed in ("fee", "transfer", "kyc", "rotation", "incident"):
        assert needed in titles, needed


def test_get_customer_lookup():
    assert data.get_customer("C-10001") is not None
    assert data.get_customer("c-10001") is not None  # case-insensitive
    assert data.get_customer("nope") is None
