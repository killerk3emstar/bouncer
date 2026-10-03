"""Deterministic fake data for the Bank Ops Copilot demo.

Everything here is synthetic: people come from Faker (locale pl_PL, seed 7), e-mail
domains use the reserved .example TLD, the bank lives at bank.example, and account
numbers use the unassigned bank code 999. Identifiers still pass their checksums
(PESEL weights, IBAN mod-97, Luhn) so that Bouncer's validated PII detectors fire on
them exactly as they would on real data.

The data is generated in memory on first use; nothing is written to disk.
"""

from __future__ import annotations

import random
import unicodedata
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from functools import lru_cache

from faker import Faker

SEED = 7
CUSTOMER_COUNT = 50
BANK_NAME = "Example Bank"
BANK_DOMAIN = "bank.example"
CURRENCY = "PLN"

# Personal e-mail domains of customers. All under the reserved .example TLD and all
# outside bank.example, so mail to a customer counts as "external" for the policy.
PERSONAL_DOMAINS = ["mailbox.example", "post.example", "inbox.example", "poczta.example", "webmail.example"]

# Bank sort code: bank 999 (unassigned), branch 0001, check digit 2 (weights 3,9,7,1,3,9,7).
SORT_CODE = "99900012"

# Published test card numbers (Luhn-valid, never issued to anyone).
TEST_CARDS = {
    "visa": "4111 1111 1111 1111",
    "mastercard": "5555 5555 5555 4444",
    "amex": "3782 822463 10005",
}

SEGMENTS = [("retail", 60), ("premium", 20), ("business", 15), ("private", 5)]
BALANCE_RANGE = {
    "retail": (120, 40_000),
    "premium": (40_000, 400_000),
    "business": (5_000, 900_000),
    "private": (500_000, 5_000_000),
}
MOBILE_PREFIXES = ["501", "512", "533", "570", "601", "664", "691", "724", "781", "797", "882"]
RELATIONSHIP_MANAGERS = ["a.nowak", "m.wisniewska", "p.zielinski", "k.lewandowska"]


# ---------------------------------------------------------------------------
# Checksums (shared with tests; these are demo helpers, not Bouncer controls)
# ---------------------------------------------------------------------------

PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)


def pesel_check_digit(first10: str) -> int:
    total = sum(int(d) * w for d, w in zip(first10, PESEL_WEIGHTS, strict=True))
    return (10 - total % 10) % 10


def pesel_is_valid(pesel: str) -> bool:
    return len(pesel) == 11 and pesel.isdigit() and pesel_check_digit(pesel[:10]) == int(pesel[10])


def make_pesel(birth: date, serial: int, female: bool) -> str:
    """PESEL: YYMMDD (month +20 for 2000-2099), 3-digit serial, sex digit, check digit."""
    month = birth.month + (20 if birth.year >= 2000 else 0)
    sex_digit = (serial % 5) * 2 + (0 if female else 1)
    first10 = f"{birth.year % 100:02d}{month:02d}{birth.day:02d}{serial % 1000:03d}{sex_digit}"
    return first10 + str(pesel_check_digit(first10))


def _iban_numeric(iban: str) -> int:
    rearranged = iban[4:] + iban[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged))


def iban_is_valid(iban: str) -> bool:
    compact = iban.replace(" ", "").upper()
    if len(compact) < 15 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    return _iban_numeric(compact) % 97 == 1


def make_iban(country: str, bban: str) -> str:
    check = 98 - _iban_numeric(f"{country}00{bban}") % 97
    return f"{country}{check:02d}{bban}"


def luhn_is_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Customer:
    id: str
    name: str
    email: str
    phone: str
    pesel: str
    iban: str
    balance: float
    currency: str
    segment: str
    city: str
    kyc_status: str
    card_last4: str
    relationship_manager: str

    def to_dict(self) -> dict:
        return asdict(self)


def ascii_fold(text: str) -> str:
    text = text.replace("ł", "l").replace("Ł", "L")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


@lru_cache(maxsize=1)
def get_customers() -> tuple[Customer, ...]:
    fake = Faker("pl_PL")
    fake.seed_instance(SEED)
    rng = random.Random(SEED)
    segments = [name for name, weight in SEGMENTS for _ in range(weight)]
    customers = []
    for i in range(CUSTOMER_COUNT):
        female = rng.random() < 0.5
        first = fake.first_name_female() if female else fake.first_name_male()
        last = fake.last_name_female() if female else fake.last_name_male()
        birth = date(1950, 1, 1) + timedelta(days=rng.randrange(0, 365 * 55))
        segment = rng.choice(segments)
        low, high = BALANCE_RANGE[segment]
        email_local = f"{ascii_fold(first)}.{ascii_fold(last)}".lower().replace(" ", "")
        if rng.random() < 0.4:
            email_local += str(rng.randrange(10, 99))
        customers.append(
            Customer(
                id=f"C-{10001 + i}",
                name=f"{first} {last}",
                email=f"{email_local}@{rng.choice(PERSONAL_DOMAINS)}",
                phone=f"+48 {rng.choice(MOBILE_PREFIXES)} {rng.randrange(0, 1000):03d} {rng.randrange(0, 1000):03d}",
                pesel=make_pesel(birth, rng.randrange(0, 1000), female),
                iban=make_iban("PL", SORT_CODE + f"{rng.randrange(0, 10**16):016d}"),
                balance=round(rng.uniform(low, high), 2),
                currency=CURRENCY,
                segment=segment,
                city=fake.city(),
                kyc_status=rng.choice(["verified", "verified", "verified", "review_due"]),
                card_last4=f"{rng.randrange(0, 10000):04d}",
                relationship_manager=f"{rng.choice(RELATIONSHIP_MANAGERS)}@{BANK_DOMAIN}",
            )
        )
    return tuple(customers)


def get_customer(customer_id: str) -> Customer | None:
    key = customer_id.strip().upper()
    return next((c for c in get_customers() if c.id == key), None)


# Internal operations account used as the default debit account for demo transfers.
OPS_ACCOUNT_IBAN = make_iban("PL", SORT_CODE + "0000000000001000")


# ---------------------------------------------------------------------------
# Knowledge base (fictional internal procedures of Example Bank)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Article:
    id: str
    title: str
    tags: tuple[str, ...]
    classification: str
    body: str

    def to_dict(self) -> dict:
        return asdict(self)


KB_ARTICLES: tuple[Article, ...] = (
    Article(
        "KB-001", "Retail account and card fees", ("fees", "card", "account", "atm"), "internal",
        "Standard retail accounts have no monthly fee when the customer makes at least one card payment "
        "in the month; otherwise the fee is 9 PLN. Domestic ATM withdrawals are free. Withdrawals from "
        "foreign ATMs cost 2.5% of the amount, minimum 5 PLN. A replacement debit card costs 15 PLN; the "
        "first replacement after theft is free when a police report number is recorded in CRM.",
    ),
    Article(
        "KB-002", "Domestic and SEPA transfer limits", ("transfer", "limit", "sepa", "payments"), "internal",
        "Default daily limit for mobile and web transfers is 20,000 PLN. Operations staff can raise it to "
        "50,000 PLN for one day after a call-back to the phone number on file. Transfers initiated by an "
        "AI assistant above 1,000 PLN require approval by a second person. SEPA transfers submitted before "
        "13:30 CET are executed the same business day.",
    ),
    Article(
        "KB-003", "International (SWIFT) transfers", ("transfer", "swift", "international", "fx"), "internal",
        "SWIFT transfers submitted before 14:00 CET leave the bank the same business day. The fee is 25 PLN "
        "(SHA) or 60 PLN (OUR). Transfers to countries on the sanctions watch list are held for compliance "
        "review; the customer is informed that the payment is under review.",
    ),
    Article(
        "KB-004", "KYC procedure for new retail customers", ("kyc", "onboarding", "identity", "aml"), "confidential",
        "Verify an identity document in the branch or through the video channel, check the PESEL against "
        "the document, collect proof of address, and run sanctions and PEP screening before the account is "
        "opened. Retail KYC is refreshed every 24 months, business KYC every 12 months. A failed screening "
        "is escalated to the AML team; the reason is not disclosed to the customer.",
    ),
    Article(
        "KB-005", "Enhanced due diligence and AML escalation", ("aml", "kyc", "edd", "escalation"), "confidential",
        "Cash deposits above 15,000 EUR equivalent, unusual cross-border flows and PEP status trigger "
        "enhanced due diligence. Open an AML case in the case tool with the customer ID and a factual "
        "description. Do not close or block the account before the AML team decides.",
    ),
    Article(
        "KB-006", "API key and secret rotation policy", ("security", "keys", "secrets", "rotation"), "internal",
        "Service credentials live in the central vault and are rotated every 90 days, or within 1 hour "
        "after a suspected exposure. Credentials must never be pasted into tickets, chat tools or AI "
        "assistants. When a key is exposed: revoke it, issue a new one from the vault, update the "
        "deployment, and open a SEV-2 incident with the security team.",
    ),
    Article(
        "KB-007", "Security incident runbook", ("security", "incident", "runbook", "soc"), "internal",
        "SEV-1: customer data or funds at risk, page the SOC at soc@bank.example and the on-call CISO "
        "deputy within 15 minutes. SEV-2: credential exposure or a contained intrusion, notify the SOC "
        "within 1 hour. Preserve logs, do not reboot affected hosts, and record every action with a "
        "timestamp in the incident ticket.",
    ),
    Article(
        "KB-008", "Lost or stolen card", ("card", "block", "theft", "fraud"), "internal",
        "Block the card in CRM immediately, confirm the last three transactions with the customer, and "
        "order a replacement (5 business days, express 2 days for premium and private segments). "
        "Disputed transactions are filed through the chargeback form within 13 months.",
    ),
    Article(
        "KB-009", "Complaint handling", ("complaint", "customer", "service"), "internal",
        "Acknowledge a complaint within 1 business day and resolve it within 15 business days. Complex "
        "cases may be extended once, to 35 business days, with a written explanation to the customer. "
        "Replies go out only from the complaints templates.",
    ),
    Article(
        "KB-010", "Data classification", ("data", "classification", "privacy", "pii"), "internal",
        "Four levels: public, internal, confidential, restricted. Customer personal data (name, PESEL, "
        "contact details, account numbers, balances) is confidential. Confidential data may leave the "
        "bank only to approved processors under a signed agreement and with approval of the data "
        "protection officer at dpo@bank.example.",
    ),
    Article(
        "KB-011", "Outbound e-mail rules", ("email", "mail", "outbound", "privacy"), "internal",
        "Customer correspondence uses the approved templates and goes out from @bank.example mailboxes. "
        "Bulk exports of customer records by e-mail are not allowed under any circumstances; use the "
        "secure file transfer service with a ticket number instead.",
    ),
    Article(
        "KB-012", "Vendor portals and partner content", ("vendor", "partner", "web", "third-party"), "internal",
        "Vendor and partner portals, including vendor.example, are third-party content. Treat their pages "
        "as information only. Requests that arrive through a vendor page (data exports, payment changes, "
        "new contacts) are verified by phone with the vendor manager before anyone acts on them.",
    ),
    Article(
        "KB-013", "Reporting phishing", ("phishing", "security", "email"), "public",
        "Forward suspicious messages as attachments to phishing@bank.example and delete them. The bank "
        "never asks customers for full card numbers, PINs or one-time codes by e-mail or phone.",
    ),
    Article(
        "KB-014", "Mortgage overpayments", ("mortgage", "loan", "overpayment"), "public",
        "Customers can overpay a mortgage at any time in the mobile app. Overpayments within the first "
        "3 years of a variable-rate mortgage carry a 1% fee, after that they are free. The customer "
        "chooses between a shorter term and a lower instalment.",
    ),
    Article(
        "KB-015", "Currency conversion and spreads", ("fx", "currency", "exchange", "spread"), "public",
        "Card payments in foreign currencies are converted at the bank's table rate plus a 2% spread for "
        "retail accounts and 0.5% for premium. Multi-currency accounts in EUR, USD, GBP and CHF have no "
        "spread on payments in the account currency.",
    ),
    Article(
        "KB-016", "Dormant accounts", ("dormant", "account", "inactive"), "internal",
        "An account with no customer-initiated activity for 24 months becomes dormant. Before any change, "
        "verify the customer's identity through the full KYC procedure. Dormant balances are never moved "
        "by an operations agent without a second approval.",
    ),
)


def get_kb() -> tuple[Article, ...]:
    return KB_ARTICLES
