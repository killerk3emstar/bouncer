"""Harmful requests to the assistant: financial crime, fraud against customers, cyberattacks, violence, self-harm.

A bank assistant is asked about money laundering every day by people whose job is to stop it, so the
topic alone is not a signal. The deterministic layer (T0) looks for three things in a user message:

- topic: a harm term of one category (launder, structuring, sanctions evasion, phishing, malware, ...),
- intent: an operational request (how do I, help me, write, draft, give me a script, jak, napisz, wie kann ich),
- concealment: the stated goal of not being noticed (without the bank noticing, to avoid AML reporting,
  so KYC does not catch it, żeby bank nie zauważył, damit die Bank keine Meldung macht).

topic + concealment, or a request to produce an attack artefact (a phishing message impersonating the bank,
ransomware, a credential stealer, a fake invoice or ID), is a strong signal: blocked at T0.
topic + intent without a defensive purpose (detect, red flags, report, training, warn customers) is a weak
signal: the pipeline asks the T2 judge the `harm` question and blocks above judge.block_above.
Everything else passes: questions about detecting, preventing or reporting abuse are normal work here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from bouncer.core import Action, Control, Finding, ScanContext, Segment, View

_F = re.IGNORECASE

# category -> topic terms (EN / PL / DE)
TOPICS: dict[str, re.Pattern[str]] = {
    "financial_crime": re.compile(
        r"\b(launder\w*|money[- ]?laundering|wash(?:ing)? (?:the )?(?:money|cash|funds)|structur\w* (?:the |my |cash |)"
        r"(?:deposits?|payments?|transfers?|cash)|smurf\w*|split\w* (?:the |my )?(?:cash|deposits?|payments?|transfers?)|"
        r"money mules?|mules? accounts?|sanction\w*|embargo\w*|tax evasion|evade (?:taxes|tax)|shell compan\w*|"
        r"front compan\w*|hide (?:the )?(?:money|funds|proceeds|income)|"
        r"pra(?:nie|ć|ł\w*) pieni\w*|wypra\w*|pieniądz\w* (?:z|ze) (?:przestępstw\w*|nielegaln\w*)|słup\w*|"
        r"spół\w* słup\w*|rozbi\w* (?:wpłat\w*|przelew\w*|gotówk\w*)|sankcj\w*|unik\w* podatk\w*|"
        r"geldwäsche|geld wasch\w*|bargeld aufteil\w*|sanktion\w*|steuerhinterzieh\w*|briefkastenfirm\w*|"
        r"verdachtsmeldung\w* (?:vermeid\w*|umgeh\w*))\b",
        _F,
    ),
    "fraud": re.compile(
        r"\b(phishing|smishing|vishing|pretend\w* to be (?:the |our |a )?bank|impersonat\w* (?:the |our |a )?(?:bank|customer|"
        r"ceo|cfo|manager)|fake (?:ids?|identit\w*|passports?|invoices?|documents?|statements?|payslips?|bank)|forg\w* "
        r"(?:a |an |the )?(?:ids?|signatures?|documents?|invoices?|statements?)|steal\w* (?:card|cards|credentials|"
        r"passwords?|identit\w*|money|funds)|card (?:skimm\w*|cloning)|carding|account takeover|take over (?:the |a )?"
        r"(?:account|accounts)|social engineer\w*|bypass\w* (?:kyc|aml|verification|2fa|mfa|sca)|(?:trick|scam|con) "
        r"(?:the |a |our )?(?:customer|customers|elderly|clients?|bank)|"
        r"podszyw\w*|wyłudz\w*|fałszyw\w* (?:dow\w*|faktur\w*|dokument\w*|sms\w*|bank\w*|stron\w*)|podrob\w*|"
        r"oszuk\w*|kod\w* blik|"
        r"betrug\w*|gefälscht\w*|fälsch\w*|phishing-?mail\w*|ausgeben als (?:die )?bank)\b",
        _F,
    ),
    "cyberattack": re.compile(
        r"\b(ransomware|malware|keylogger|trojan\w*|botnet|rootkit|spyware|infostealer|credential (?:stealer|harvest\w*)|"
        r"(?:ddos|dos) (?:attack|the)|exploit (?:for|the|a) |sql injection (?:against|on|into)|brute[- ]?force (?:the |a |"
        r"customer )?(?:logins?|passwords?|accounts?|pins?)|crack (?:the |a )?(?:passwords?|pins?)|"
        r"(?:log|capture|record|harvest|grab|collect|steal|sniff|intercept)\w* (?:the |all |our |customers'? |clients'? |"
        r"users'? )?(?:online banking |banking |login |mobile banking )?(?:passwords?|credentials|keystrokes|card numbers|pins?|"
        r"otp codes?|one-time codes?)|"
        r"zaszyfr\w* (?:dysk\w*|serwer\w*|plik\w*)|złośliw\w* oprogramow\w*|wirus\w*|schadsoftware|erpressungs\w*)\b",
        _F,
    ),
    "violence": re.compile(
        r"\b(make|build|assemble) (?:a |an )?(?:bomb|explosive|pipe bomb|gun)|\b(kill|poison|hurt|attack) (?:the |my |a |our )?"
        r"(?:manager|colleague|customer|teller|boss|people|someone)|\b(zabi\w*|otru\w*) |\bbomb\w*\b",
        _F,
    ),
    "self_harm": re.compile(
        r"\b(kill myself|end my life|suicide method|how to (?:commit )?suicide|hurt myself|self[- ]harm|"
        r"zabić się|odebrać sobie życie|popełnić samobójstwo|mich umbringen)\b",
        _F,
    ),
}

# The stated goal of not being noticed by the bank, compliance or the authorities.
CONCEAL = re.compile(
    r"(without (?:the |our |my )?(?:bank|anyone|compliance|police|authorities|them|it) (?:noticing|knowing|finding out|"
    r"detecting|seeing)|without (?:it |them |this )?being (?:flagged|noticed|detected|reported|traced)|"
    r"(?:avoid|evade|bypass|get around|circumvent|beat|dodge|escape|slip past|stay under)\w* (?:the |any )?"
    r"(?:aml|kyc|reporting|reports?|detection|monitoring|screening|sanctions?|thresholds?|limits?|ctr|compliance|"
    r"the radar|radar|flags?|alerts?|checks?|taxes|tax)|under the radar|not (?:be|get|being|getting) (?:flagged|caught|"
    r"noticed|detected|reported)|so (?:that )?(?:the )?(?:bank|kyc|aml|compliance|they|nobody|no one|it)\w* "
    r"(?:does ?n[o']?t|do ?n[o']?t|won'?t|can'?t|cannot|will not|never) (?:catch|notice|flag|detect|see|report|find)|"
    r"(?:look|looks) (?:legit\w*|legal|normal|clean)|untraceabl\w*|"
    r"żeby (?:bank|nikt|urząd|policja|giif|oni)\w* nie (?:zauważ\w*|wykry\w*|zgłosi\w*|złapa\w*|wiedzia\w*)|"
    r"bez wiedzy|obej\w*|omin\w*|unikn\w* (?:zgłosze\w*|raport\w*|kontrol\w*|wykryci\w*)|"
    r"damit (?:die bank|niemand|keiner|es) (?:\w+ )?(?:keine|nicht|nichts) (?:\w+ )?(?:merkt|meldet|bemerkt|"
    r"verdachtsmeldung|auffällt|entdeckt)|umgeh\w*|unbemerkt|ohne dass (?:die bank|jemand))",
    _F,
)

# An operational request: the user wants it done or explained step by step.
INTENT = re.compile(
    r"(\b(how (?:do|can|could|would|should) (?:i|we|you|one)|how to|help me|teach me|show me|tell me how|explain how|"
    r"give me|write|draft|compose|create|generate|build|make|code|prepare|set up|step[- ]by[- ]step|best way to|"
    r"what(?:'s| is) the (?:best|easiest|safest) way)\b|"
    r"\b(jak (?:mogę|można|to|najlepiej|zrobić|szybko|)|pomóż|napisz|przygotuj|stwórz|wygeneruj|daj mi|pokaż|wyjaśnij jak)|"
    r"\b(wie (?:kann|könnte|soll) (?:ich|man|wir)|hilf mir|schreib\w*|erstell\w*|zeig mir))",
    _F,
)

# A defensive purpose: detecting, preventing, reporting or training. Not escalated (unless there is concealment).
DEFENSIVE = re.compile(
    r"\b(detect\w*|spot\w*|recogni[sz]\w*|identify|identif\w*|red flags?|warning signs?|indicators?|typolog\w*|"
    r"prevent\w*|protect\w*|report\w* (?:to|a|the|it|suspicious)|suspicious activity report|sar\b|str\b|investigat\w*|"
    r"train\w*|awareness|educat\w*|warn\w* (?:customers?|clients?|staff|tellers?|people|about|against)|warning about|"
    r"notice to customers|simulat\w*|course|lecture|workshop|kurs\w*|in general terms|"
    r"policy|procedure|regulation|regulator\w*|compliance team|what (?:is|are) (?:the )?(?:typical|common)|"
    r"wykry\w*|rozpozna\w*|sygnał\w* ostrzegawcz\w*|zgłos\w*|zapobieg\w*|ostrzeż\w*|ostrzega\w*|szkoleni\w*|procedur\w*|"
    r"erkenn\w*|melden|warnsignal\w*|schulung\w*|verhinder\w*)",
    _F,
)

# Requests for an attack artefact are strong without any concealment phrase.
ARTEFACT = re.compile(
    r"((write|draft|compose|create|generate|make|prepare|napisz|przygotuj|stwórz|schreib\w*|erstell\w*)\b[^.?!\n]{0,60}"
    r"\b(phishing|smishing|sms|e-?mail|message|wiadomoś\w*|mail\w*|nachricht\w*|page|stron\w*)\b[^.?!\n]{0,80}"
    r"\b(pretend\w*|impersonat\w*|posing as|as (?:if from |)(?:the |our )?bank|from (?:the |our )?bank asking|"
    r"podszywaj\w*|podszyw\w*|jako bank|als (?:die )?bank|asking (?:customers|clients|them|users) (?:for|to)|"
    r"(?:pin|password|hasło|blik|cvv|card number|login))|"
    r"(write|create|generate|build|code|make|napisz|stwórz|schreib\w*)\b[^.?!\n]{0,40}\b(ransomware|keylogger|"
    r"infostealer|credential stealer|trojan|malware|botnet|wirus\w*|schadsoftware)\b|"
    r"(write|create|generate|make|draft|prepare|forge|napisz|przygotuj|stwórz|podrób)\b[^.?!\n]{0,40}\b(fake|"
    r"forged|fałszyw\w*|podrobion\w*|gefälscht\w*) (ids?|identit\w*|passports?|invoices?|faktur\w*|documents?|"
    r"dokument\w*|statements?|payslips?|dow\w*))",
    _F,
)


@dataclass(frozen=True)
class HarmSignal:
    category: str
    strength: str  # "strong" (blocked at T0) or "weak" (asked to the T2 judge)
    why: str
    evidence: str


def assess(text: str, categories: list[str] | None = None) -> HarmSignal | None:
    """Classify one user message. Pure and fast (a few regex scans)."""
    if not text or not text.strip():
        return None
    allowed = set(categories) if categories else set(TOPICS)
    art = ARTEFACT.search(text)
    if art and (CONCEAL.search(text) or not DEFENSIVE.search(text)):
        groups = " ".join(g.lower() for g in art.groups() if g)
        if any(w in groups for w in ("ransomware", "keylogger", "stealer", "trojan", "malware", "botnet", "wirus", "schadsoftware")):
            cat = "cyberattack"
        else:
            cat = "fraud"
        if cat in allowed:
            return HarmSignal(cat, "strong", "a request to produce an attack artefact", _snip(text, art))
    for cat, pat in TOPICS.items():
        if cat not in allowed:
            continue
        m = pat.search(text)
        if not m:
            continue
        conceal = CONCEAL.search(text)
        if conceal:
            return HarmSignal(cat, "strong", f"'{m.group(0).strip()}' together with an aim to avoid detection", _snip(text, conceal))
        if cat in ("violence", "self_harm"):
            return HarmSignal(cat, "weak", f"'{m.group(0).strip()}'", _snip(text, m))
        if INTENT.search(text) and not DEFENSIVE.search(text):
            return HarmSignal(cat, "weak", f"an operational request about '{m.group(0).strip()}'", _snip(text, m))
    return None


def _snip(text: str, m: re.Match[str]) -> str:
    s = m.group(0).strip()
    return s if len(s) <= 80 else s[:77] + "..."


CATEGORY_LABEL = {
    "financial_crime": "financial crime (money laundering, structuring, sanctions or tax evasion)",
    "fraud": "fraud against customers or the bank (phishing, impersonation, forged documents, account takeover)",
    "cyberattack": "a cyberattack (malware, credential theft, attacks on systems)",
    "violence": "violence or weapons",
    "self_harm": "self-harm",
}


class HarmfulContentControl(Control):
    id = "harmful_content"
    owasp_llm: list[str] = []
    owasp_agentic: list[str] = []

    def applies_to(self, segment: Segment) -> bool:
        return segment.direction == "input" and segment.role == "user"

    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        cfg: Any = self.cfg
        text = views[0].text if views else segment.text
        sig = assess(text, list(cfg.categories))
        if sig is None or sig.strength != "strong":
            return []  # weak signals are judged by T2 in the pipeline (Engine._semantic_harm)
        return [
            Finding(
                control=self.id,
                rule=sig.category,
                severity="critical" if sig.category in ("self_harm", "violence") else "high",
                action=Action.parse(cfg.action),
                message=(
                    f"The message asks for help with {CATEGORY_LABEL[sig.category]}: {sig.why}. The assistant does not "
                    "help with that. Questions about detecting, preventing or reporting such activity are allowed; "
                    "rephrase it that way or contact compliance."
                ),
                evidence=sig.evidence,
                atlas=["AML.T0048.000"] if sig.category in ("financial_crime", "fraud") else ["AML.T0048.003"],
            )
        ]
