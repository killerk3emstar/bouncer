"""Prompt injection heuristics, T0 (control id "prompt_injection", rules "heuristic.<pattern-id>").

Known phrasings of instruction override (EN, PL, DE, FR, ES, IT, PT, RU), chat-template tokens, fake
system blocks, prompt-leak requests, jailbreak personas, and markers of tool poisoning and hidden
exfiltration instructions in tool results and tool definitions.

The patterns run on the normalized view (lowercase, lookalike letters and leetspeak folded, spaced-out
letters joined), on the lowercased raw text (for tokens, file paths and e-mail addresses that the
normalized view would fold), and on every decoded view (base64, hex, url, rot13, reversed, hidden
Unicode tags). Precision matters as much as recall: phrases such as "ignore the noise in this chart",
"act as a reviewer" or "zignoruj poprzedni wykres" must not fire, so every family needs a target
(instructions, rules, system prompt) and a qualifier (previous, all, your, system).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from bouncer.controls.normalize import normalize_text
from bouncer.core import Action, Control, Finding, ScanContext, Segment, View
from bouncer.policy.schema import PromptInjectionCfg

MAX_SCAN_CHARS = 100_000
UNTRUSTED_ROLES = frozenset({"tool_result", "tool_definition"})

# MITRE ATLAS ids verified in mitre-atlas/atlas-data dist/ATLAS.yaml:
# AML.T0051 LLM Prompt Injection (.000 Direct, .001 Indirect), AML.T0054 LLM Jailbreak,
# AML.T0056 Extract LLM System Prompt.
ATLAS_DIRECT = "AML.T0051.000"
ATLAS_INDIRECT = "AML.T0051.001"

S = r"[^a-z0-9]{0,4}"  # separator between words in the normalized view (may be empty after joining)


@dataclass(frozen=True, slots=True)
class Pattern:
    id: str
    family: str  # human description used in messages
    severity: str
    regex: re.Pattern[str]
    keywords: tuple[str, ...]  # prefilter: at least one must occur in the scanned text
    texts: tuple[str, ...] = ("norm",)  # "norm" (normalized) and/or "raw" (lowercased raw)
    roles: frozenset[str] | None = None  # None = every role in apply_to
    validate: Callable[[re.Match[str]], bool] | None = None
    atlas: tuple[str, ...] = ()


def _c(p: str) -> re.Pattern[str]:
    return re.compile(p, re.MULTILINE)


# --------------------------------------------------------------------------- vocabulary

VERB_EN = (
    r"(?:ignore|ignoring|disregard|disregarding|forget|forgetting|skip|override|overriding|bypass|bypassing|"
    r"neglect|overlook|discard|abandon|set aside|throw out|stop following|do not follow|don'?t follow|"
    r"dont follow|no longer follow|cancel|nullify|void)"
)
QUAL_EN = (
    r"(?:all|any|every|each|the|your|these|those|of|and|previous|previously|prior|earlier|preceding|above|"
    r"foregoing|aforementioned|initial|original|old|system|developer|existing|current|safety|ethical|default|"
    r"programmed|given|everything|that|you|were|have|been|told|so|far|before|until|now|other|preset|built-in|"
    r"hidden|internal|standing|base|core|operating|openai|anthropic|content|security)"
)
OBJ_EN = (
    r"(?:instructions?|instruction set|directions?|directives?|rules?|guidelines?|prompts?|commands?|orders?|"
    r"programming|guardrails?|restrictions?|constraints?|policies|policy|safeguards?|filters?|limitations?|"
    r"context|training|system prompt|system message|messages?|conversation|guidance|protocols?|principles)"
)
STRONG_EN = re.compile(
    r"\b(?:all|any|every|previous|previously|prior|earlier|preceding|above|foregoing|aforementioned|initial|"
    r"original|system|your|developer|safety|ethical|programmed|old|existing|hidden|internal|built-in|"
    r"preset|standing|base|core|operating|openai|anthropic|security|so far|until now|before|given|received)\b"
)
SELF_REF = re.compile(r"\b(?:my|i|we|our|me)\b")
AI_WORDS = (
    r"(?:ai assistant|ai agent|ai model|language model|a\.i\.|ai|llm|assistant|chatbot|chatgpt|gpt|claude|copilot|"
    r"gemini|model)"
)
EMAIL = r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"
URL = r"https?://[^\s\"'<>]+"
DATA_WORDS = (
    r"(?:(?:customer|client|user|employee|account|patient|member|contact)s?'? ?(?:list|data|records?|details|"
    r"database|e-?mails?|contacts|information|info|pii|names|addresses|accounts|numbers|files)|"
    r"all (?:the )?(?:customers|clients|users|records|data|e-?mails|contacts|accounts|files|documents|messages)|"
    r"credentials|passwords?|api ?keys?|secrets?|access tokens?|tokens|private keys?|ssh keys?|"
    r"(?:conversation|chat|message) history|system prompt|account (?:numbers|balances|details)|"
    r"personal (?:data|information)|card numbers|pesel|ibans?|the (?:full|entire|whole|complete) "
    r"(?:list|database|conversation|history|file)|contents? of|dane klient[oó]w|list[eęa] klient[oó]w|"
    r"klient[oó]w|has[lł]a|dane osobowe|histori[eę] rozmowy)"
)


# Verbs that are everyday technical vocabulary ("override the settings", "skip the step", "bypass the
# proxy"): with these, only objects that belong to an AI assistant count.
TECH_VERBS = re.compile(r"^(?:override|overriding|bypass|bypassing|skip|cancel|nullify|void|discard|abandon|throw out)$")
AI_OBJECTS = re.compile(
    r"^(?:instructions?|instruction set|directives?|prompts?|system prompt|system message|programming|guardrails?|"
    r"safeguards?|guidelines?|training|safety (?:rules?|guidelines?|filters?))$"
)


def _v_override(m: re.Match[str]) -> bool:
    if SELF_REF.search(m.group(0)):
        return False
    g = m.groupdict()
    verb = (g.get("verb") or "").strip()
    obj = (g.get("obj") or "").strip()
    q = g.get("q") or ""
    if TECH_VERBS.match(verb):
        ai_target = AI_OBJECTS.match(obj) and re.search(r"\b(?:your|previous|prior|above|system|safety|initial|original|all)\b", q)
        if not ai_target and not re.search(r"\byour\b", q):
            return False
    if g.get("tail"):
        return True
    return bool(STRONG_EN.search(q))


def _v_no_self(m: re.Match[str]) -> bool:
    return not SELF_REF.search(m.group(0))


def _v_pl(m: re.Match[str]) -> bool:
    return not re.search(r"\bmoj\w*\b|\bnasz\w*\b", m.group(0))


# --------------------------------------------------------------------------- patterns

PATTERNS: list[Pattern] = [
    # ---- instruction override
    Pattern(
        "ignore-previous", "instruction override", "high",
        _c(
            rf"\b(?P<verb>{VERB_EN})\b(?P<q>(?:{S}{QUAL_EN}\b){{0,6}}){S}(?P<obj>{OBJ_EN})\b"
            rf"(?!{S}(?:i|we) (?:gave|sent|wrote|provided|mentioned|shared|added|asked|just))"
            rf"(?P<tail>{S}(?:above|before|so far|until now|earlier|previously|given (?:to you|above|earlier|before)|"
            rf"you (?:were|have been|got) given|you received|from (?:before|earlier|the system|your (?:developers?|creators?)))\b)?"
        ),
        ("ignor", "disregard", "forget", "skip", "overrid", "bypass", "neglect", "overlook", "discard", "abandon",
         "aside", "throw", "follow", "cancel", "nullify", "void"),
        validate=_v_override,
    ),
    Pattern(
        "ignore-previous", "instruction override", "high",
        _c(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:of\s+)?(?:the|what(?:'s| is)?)\s+(?:above|previous|prior|preceding)"
           r"(?=\s*(?:$|[.,;:!]|and\b|then\b|instead\b|now\b))"),
        ("ignore", "disregard", "forget"),
    ),
    Pattern(
        "ignore-previous", "instruction override", "high",
        _c(
            r"\byour (?:previous |prior |original |system |old |current )?(?:instructions|rules|guidelines|programming|"
            r"directives|restrictions|policies) (?:are|is|have been) (?:now |hereby )?(?:void|null|nullified|cancell?ed|"
            r"revoked|obsolete|invalid|no longer valid|overridden|suspended|lifted|disabled)\b"
            r"|\byou (?:no longer|don'?t|do not|dont) (?:have|need) to (?:follow|obey|comply with|respect|adhere to|abide by)\s+"
            r"(?:your |any |the |openai'?s? |anthropic'?s? |safety |content |ethical |system )+(?:policies|policy|guidelines|"
            r"rules|instructions|restrictions|programming|guardrails)\b"
        ),
        ("your", "you no longer", "you don", "you do not", "you dont"),
    ),
    Pattern(
        "forget-everything", "instruction override (Polish)", "high",
        _c(
            r"\b(?:zapomnij|zignoruj|pomin|olej)(?: o)? (?:wszystko|wszystkim|cale|calej|calosc)\b[^.\n]{0,30}?"
            r"\b(?:wczesniej|powyzej|co ci (?:powiedziano|kazano|napisano|przekazano)|co (?:dostales|otrzymales|wiesz)|"
            r"do tej pory|dotychczas|z promptu|z instrukcji)"
        ),
        ("zapomnij", "zignoruj", "pomin", "olej"),
        validate=lambda m: not re.search(r"\b(?:mowilem|pisalem|wyslalem|prosilem|mowilam|pisalam|prosilam)\b", m.group(0)),
    ),
    Pattern(
        "forget-everything", "instruction override", "high",
        _c(
            rf"\b{VERB_EN}{S}(?:everything|anything|all(?: of)?(?: that| this)?|whatever)"
            rf"(?:{S}(?:that|this|you|were|was|have|had|been|told|said|written|stated|given|learned|know|in|the|is|it))*?"
            rf"{S}(?:above|before|previously|earlier|so far|until now|you (?:were|have been) told|you know|you were given)\b"
        ),
        ("ignor", "disregard", "forget", "discard", "overlook"),
        validate=_v_no_self,
    ),
    Pattern(
        "new-instructions", "replacement instructions in untrusted content", "medium",
        _c(
            r"(?:\b(?:new|updated|revised|real|actual|true|secret|hidden|override|important) (?:system )?"
            r"(?:instructions?|directives?|orders|task|objective)\s*:|\byour (?:new|updated|real|actual|true|only) "
            r"(?:instructions|task|goal|objective|directive|purpose|role|job) (?:is|are|will be)\b)"
        ),
        ("instruction", "directive", "orders", "task", "objective", "goal", "purpose", "role", "job"),
        roles=UNTRUSTED_ROLES,
    ),
    Pattern(
        "persona-switch", "role reassignment", "high",
        _c(
            r"\byou are now (?:a |an |the )?(?:(?:new|different|unrestricted|unfiltered|uncensored|jailbroken|"
            r"evil|rogue|free|liberated|unlocked|amoral|unbound|unchained|dan|stan|dude|aim)\b|in \w+ mode\b|"
            r"no longer\b|(?:going to|gonna) (?:act|pretend|play|roleplay|role-play|be)\b|acting as\b|"
            r"playing (?:the role|as)\b|(?:called|named|known as)\b|"
            r"(?:ai|assistant|model|chatbot|bot|llm)s? (?:without|with no|free of|that has no|that ignores)\b)"
            r"|\bfrom now on,? you(?: will| shall| must| are going to| are| can| have)? (?:be |act as |pretend |"
            r"respond as |answer as |behave as )?(?:an? )?(?:dan\b|evil|unrestricted|unfiltered|uncensored|"
            r"jailbroken|free\b|no longer|without|not (?:follow|obey|refuse|comply)|ignore|disregard|have no|"
            r"never refuse|answer without|respond without|do anything)"
        ),
        ("you are now", "from now on"),
    ),
    Pattern(
        "persona-switch", "role reassignment in untrusted content", "high",
        _c(r"\bfrom now on,? (?:you|the assistant|assistant)\b(?: will| must| should| shall| are| need to)\b"),
        ("from now on",),
        roles=UNTRUSTED_ROLES,
    ),
    # ---- Polish / German / other languages
    Pattern(
        "ignore-previous-pl", "instruction override (Polish)", "high",
        _c(
            r"\b(?:zignoruj(?:cie)?|ignoruj(?:cie)?|pomin(?:cie)?|zapomnij(?:cie)?(?: o)?|olej|odrzuc(?:cie)?|"
            r"zlekcewaz|nie (?:stosuj sie do|przestrzegaj|sluchaj|wykonuj|bierz pod uwage|trzymaj sie)|"
            r"przestan (?:stosowac sie do|przestrzegac|sluchac|wykonywac))"
            r"(?:\s+(?:wszystkie|wszystkich|wszelkie|wszelkich|cale|calej|twoje|twoich|swoje|swoich|dotychczasowe|"
            r"dotychczasowych|wczesniejsze|wczesniejszych|poprzednie|poprzednich|powyzsze|powyzszych|systemowe|"
            r"systemowych|otrzymane|otrzymanych|pierwotne|pierwotnych|oryginalne|oryginalnych|te|tamte|zadane|"
            r"zadanych|bezpieczenstwa|dane ci|ci dane|ktore|otrzymales|dostales|wczesniej|do tej pory)){1,5}"
            r"\s+(?:polecenia|polecen|poleceniach|polecenie|instrukcje|instrukcji|instrukcjach|instrukcja|zasady|"
            r"zasad|zasadach|reguly|regul|regulach|wytyczne|wytycznych|ustawienia|ograniczenia|ograniczen|"
            r"zabezpieczenia|zabezpieczen|prompt|prompty|komendy|rozkazy|zalecenia|zalecen)\b"
        ),
        ("zignoruj", "ignoruj", "pomin", "zapomnij", "olej", "odrzuc", "zlekcewaz", "nie ", "przestan"),
        validate=_v_pl,
    ),
    Pattern(
        "ignore-previous-pl", "instruction override (Polish)", "high",
        _c(
            r"\b(?:zignoruj(?:cie)?|ignoruj(?:cie)?|pomin(?:cie)?|zapomnij(?:cie)? o|olej|odrzuc(?:cie)?|"
            r"nie (?:stosuj sie do|przestrzegaj|sluchaj|wykonuj))\s+(?:polecenia|polecen|poleceniach|instrukcje|instrukcji|"
            r"instrukcjach|zasady|zasad|reguly|regul|wytyczne|wytycznych|ograniczenia|ograniczen|prompt)"
            r"[,]?\s+(?:systemowe|systemowych|systemu|wczesniejsze|wczesniejszych|poprzednie|poprzednich|powyzsze|"
            r"powyzszych|dotychczasowe|otrzymane|bezpieczenstwa|(?:ktore|jakie) (?:dostales|otrzymales|masz|ci (?:dano|podano))|"
            r"od (?:tworcow|administratora|systemu))\b"
        ),
        ("zignoruj", "ignoruj", "pomin", "zapomnij", "olej", "odrzuc", "nie "),
    ),
    Pattern(
        "persona-switch", "role reassignment (Polish)", "high",
        _c(
            r"\bod (?:teraz|tej chwili|dzis)(?: juz)?,? (?:jestes|bedziesz|stajesz sie|dzialasz jako|udajesz)"
            r"(?: teraz)?(?: \w+){0,2}? (?:dan\b|nieograniczon\w*|niecenzurowan\w*|bez (?:ograniczen|zasad|filtrow|cenzury|regul)|"
            r"zl\w+ (?:ai|asystent\w*|model\w*)|wolnym|innym (?:ai|asystentem|modelem)|w trybie\b)"
            r"|\bod (?:teraz|tej chwili),? (?:nie musisz|nie obowiazuja cie|ignorujesz|nie przestrzegasz|"
            r"mozesz (?:wszystko|robic wszystko)|nie masz (?:zadnych )?(?:ograniczen|zasad))"
        ),
        ("od teraz", "od tej chwili", "od dzis"),
    ),
    Pattern(
        "ignore-previous-de", "instruction override (German)", "high",
        _c(
            r"\b(?:ignoriere|ignorier|ignorieren sie|ignoriert|vergiss|vergessen sie|vergesst|missachte|"
            r"missachten sie|uberspringe|ubergehe|verwirf|setze|befolge nicht|befolgen sie nicht)"
            r"(?:\s+(?:alle|samtliche|jegliche|deine|ihre|die|der|den|vorherigen|vorigen|bisherigen|obigen|fruheren|"
            r"vorangegangenen|vorhergehenden|ursprunglichen|system|bisher|gegebenen|erhaltenen)){1,5}"
            r"\s+(?:anweisungen|anweisung|instruktionen|befehle|regeln|vorgaben|richtlinien|anordnungen|prompts?|"
            r"einschrankungen|systemanweisungen|systemprompts?|sicherheitsregeln)\b"
        ),
        ("ignor", "vergiss", "vergess", "missacht", "uberspring", "ubergeh", "verwirf", "setze", "befolge"),
    ),
    Pattern(
        "persona-switch", "role reassignment (German)", "high",
        _c(
            r"\b(?:du bist|sie sind) (?:jetzt|nun|ab sofort|ab jetzt) (?:ein |eine )?(?:dan\b|unzensiert\w*|"
            r"uneingeschrankt\w*|ohne (?:einschrankungen|regeln|filter|zensur)|im \w+modus|bose\w*|frei\w*)"
        ),
        ("du bist", "sie sind"),
    ),
    Pattern(
        "ignore-previous-intl", "instruction override (French/Spanish/Italian/Portuguese/Russian)", "high",
        _c(
            r"\b(?:ignore[zs]?|oublie[zs]?|neglige[zs]?) (?:toutes? |tous )?(?:les |tes |vos )?"
            r"(?:instructions|consignes|regles|directives)(?: (?:precedentes|anterieures|ci-dessus|du systeme|"
            r"initiales))\b"
            r"|\b(?:ignore[zs]?|oublie[zs]?) (?:toutes|tous) (?:les |tes |vos )(?:instructions|consignes|regles|directives)\b"
            r"|\b(?:ignora|ignore|olvida|olvide|descarta|omite)(?:r)? (?:todas? )?(?:las |tus |sus )?"
            r"(?:instrucciones|reglas|indicaciones|directrices) (?:anteriores|previas|de arriba|del sistema|iniciales)\b"
            r"|\b(?:ignora|olvida) todas (?:las |tus )(?:instrucciones|reglas|indicaciones)\b"
            r"|\b(?:ignora|dimentica|tralascia)(?: tutte)? (?:le )?(?:istruzioni|regole|indicazioni) "
            r"(?:precedenti|sopra|di sistema|iniziali)\b"
            r"|\b(?:ignora|dimentica) tutte le (?:istruzioni|regole|indicazioni)\b"
            r"|\b(?:ignore|ignora|esqueca|desconsidere)(?: todas)? (?:as )?(?:instrucoes|regras) (?:anteriores|previas|acima)\b"
            r"|(?:проигнорируи|игнорируи|забудь|отбрось|не обращаи внимания на)(?:те)?\s+(?:(?:все|bce|всe|вce|"
            r"предыдущие|прежние|предшествующие|системные|свои|твои|данные|тебе|bыше|выше)\s+){1,4}"
            r"(?:инструкции|указания|правила|команды|промпт|ограничения)"
        ),
        ("ignor", "oubli", "neglig", "olvid", "descart", "omit", "dimentic", "tralasci", "esquec", "desconsider",
         "игнор", "забуд", "отбрось", "не обращаи"),
    ),
    # ---- chat template tokens and fake system blocks
    Pattern(
        "chat-template-token", "chat template token", "high",
        _c(
            r"<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|end_of_text|begin_of_text|start_header_id|"
            r"end_header_id|eot_id|eom_id|start_of_turn|end_of_turn|fim_prefix|fim_middle|fim_suffix|tool_call|"
            r"python_tag|channel|message|start|end|return|constrain)\|>"
            r"|\[/?inst\]|<</?sys>>|<(?:start|end)_of_turn>|</s>\s*(?:<s>|\[inst\]|system|user|assistant|human)"
            r"|<s>\s*\[inst\]"
            r"|###\s*instruction:[\s\S]{0,2000}?###\s*response:"
        ),
        ("<|", "[inst]", "[/inst]", "<<sys>>", "<</sys>>", "_of_turn>", "</s>", "<s>", "### instruction", "###instruction"),
        texts=("raw", "norm"),
    ),
    Pattern(
        "fake-system-block", "fake system or developer block", "high",
        _c(
            r"\b(?:system|admin|administrator|developer|root|sudo)\s+override\b"
            r"|\[\s*(?:system|developer|admin|sys|operator)\s*(?:message|prompt|instructions?|note|override|update|"
            r"command|directive|notice)\s*\]"
            r"|\[\s*(?:system|developer|admin)\s*\]\s*:"
            r"|<\s*/?\s*(?:system|system[_ -]prompt|sys|developer|developer[_ -]message|system[_ -]instructions?|"
            r"admin[_ -]instructions?)\s*>"
            r"|^#{1,6} ?(?:system|developer|admin)(?: (?:prompt|message|instructions?|override|note))?:?\n"
            r"(?=(?:you|ignore|new|from now|always|never|do not|dont|the assistant|assistant|disregard|forget)\b)"
            r"|^#{1,6} ?(?:system|developer) (?:prompt|message|instructions?|override)\b"
            r"|^(?:system|developer) (?:prompt|message|instructions?) ?(?:override|update)?:"
        ),
        ("system", "admin", "developer", "root", "sudo", "sys", "operator"),
    ),
    Pattern(
        "policy-puppetry", "fake policy configuration block", "high",
        _c(r"<\s*/?\s*(?:interaction-config|blocked-modes|allowed-modes|blocked-strings?|allowed-responses|"
           r"blocked-responses|request interaction-mode|dr-house-config)\b"),
        ("interaction-config", "blocked-", "allowed-", "interaction-mode", "dr-house"),
        texts=("raw", "norm"),
    ),
    Pattern(
        "role-json", "chat message with a system role inside a tool result", "high",
        _c(r"[\"']role[\"']\s*:\s*[\"'](?:system|developer)[\"']"),
        ("role",),
        texts=("raw",),
        roles=UNTRUSTED_ROLES,
    ),
    # ---- prompt leak
    Pattern(
        "prompt-leak", "system prompt extraction", "medium",
        _c(
            r"\b(?:repeat|print|show|reveal|display|output|tell|give|leak|dump|share|disclose|spell out|recite|"
            r"write out|type out|copy|paste|return|echo|expose|provide|send)(?: me| us)?(?: back)?"
            r"(?:\s+(?:all|the|of|entire|full|whole|exact|verbatim|original|complete|initial|hidden|secret|your))*\s+"
            r"(?:system prompt|system message|system instructions|initial (?:instructions|prompt)|original "
            r"(?:instructions|prompt)|hidden (?:instructions|prompt)|secret (?:instructions|prompt)|pre-?prompt|"
            r"developer (?:message|prompt|instructions)|instructions you (?:were|have been) given|"
            r"(?:your|the assistant'?s) (?:instructions|prompt|initialization|configuration|guidelines|directives)|"
            r"(?:text|words|everything|instructions|content) (?:above|before this)|conversation so far|"
            r"context window)\b"
        ),
        ("repeat", "print", "show", "reveal", "display", "output", "tell", "give", "leak", "dump", "share",
         "disclose", "spell", "recite", "write", "type", "copy", "paste", "return", "echo", "expose", "provide", "send"),
        atlas=("AML.T0056",),
    ),
    Pattern(
        "prompt-leak", "system prompt extraction", "medium",
        _c(
            r"\brepeat\b(?:\s+(?:back|out))?\s+(?:everything|all|the (?:text|words|message|content|lines)|what(?:'s| is| was)?)"
            r"(?:\s+(?:written|said|stated|that|is|was|you|have|been|given|sent|told))*\s+(?:above|before this|so far|"
            r"prior to this|from the (?:start|beginning)|at the (?:start|beginning))"
            r"|\bwhat(?:'s| is| are| was| were)\s+(?:in\s+)?your\s+(?:(?:initial|original|system|hidden|secret|exact|"
            r"first|full|complete|real)\s+(?:instructions|prompt|guidelines|directives|rules|message)|system\s+prompt|prompt)\b"
            r"|\bwhat (?:instructions|rules|guidelines) (?:were|have) you (?:been )?given\b"
            r"|\b(?:first|last|opening|initial|second) (?:line|sentence|word|paragraph|words|lines)s? of (?:your|the) "
            r"(?:instructions|prompt|system prompt|system message|initial prompt)\b"
            r"|\b(?:starting|beginning|that (?:start|begin)s?) with [\"']?you are\b"
        ),
        ("repeat", "what", "starting", "beginning", "start", "begin", "first", "last", "opening", "initial", "second"),
        atlas=("AML.T0056",),
    ),
    Pattern(
        "prompt-leak-pl", "system prompt extraction (Polish)", "medium",
        _c(
            r"\b(?:pokaz|wyswietl|podaj|wypisz|powtorz|zdradz|ujawnij|wklej|przepisz|napisz|wyslij)(?: mi| nam)?"
            r"(?:\s+(?:caly|cala|cale|swoj|twoj|swoje|twoje|swoja|twoja|dokladnie|doslownie|ten|ta|te))*\s+"
            r"(?:prompt systemowy|systemowy prompt|prompt systemu|instrukcje systemowe|polecenia systemowe|"
            r"wiadomosc systemowa|instrukcje poczatkowe|poczatkowe instrukcje|ukryte instrukcje|"
            r"(?:swoj|twoj) prompt|(?:swoje|twoje) (?:instrukcje|polecenia|wytyczne)|wszystko (?:co jest )?powyzej|"
            r"tekst powyzej)\b"
            r"|\bjaki(?:e)? (?:jest|sa|byl|byly) (?:twoj|twoje|twoja) (?:prompt|instrukcje|polecenia|wytyczne|"
            r"prompt systemowy|instrukcje systemowe)\b"
        ),
        ("pokaz", "wyswietl", "podaj", "wypisz", "powtorz", "zdradz", "ujawnij", "wklej", "przepisz", "napisz",
         "wyslij", "jaki"),
        atlas=("AML.T0056",),
    ),
    Pattern(
        "prompt-leak-de", "system prompt extraction (German)", "medium",
        _c(
            r"\b(?:zeige|zeig|gib|nenne|wiederhole|verrate|schreibe|drucke)(?: mir| uns)?(?: bitte)?\s+(?:deinen|deine|"
            r"den|die|ihren|ihre)\s+(?:system ?prompt|systemanweisungen|system-anweisungen|ursprunglichen anweisungen|"
            r"anfanglichen anweisungen|anweisungen|instruktionen)\b"
        ),
        ("zeig", "gib", "nenne", "wiederhole", "verrate", "schreibe", "drucke"),
        atlas=("AML.T0056",),
    ),
    # ---- jailbreak personas
    Pattern(
        "jailbreak-persona", "jailbreak persona (DAN family)", "high",
        _c(
            r"\bdo anything now\b"
            r"|\b(?:you are|you're|youre|act as|acting as|pretend to be|pretend you are|roleplay as|role-play as|"
            r"play the role of|become|simulate|be)\s+(?:a |an |the )?(?:dan|stan|dude|aim|evilbot|evil-bot|"
            r"evil confidant|mongo tom|jailbreak|jailbroken (?:ai|model|assistant|chatbot|version)|"
            r"(?:unfiltered|uncensored|unrestricted|amoral|unethical|unaligned) (?:ai|model|assistant|chatbot|version|llm))"
            r"\b(?!'s|’s)"
            r"|\bstay in character\b.{0,60}\b(?:dan|no matter what|never break|always answer)"
        ),
        ("anything now", "dan", "stan", "dude", "aim", "evil", "mongo", "jailbr", "unfiltered", "uncensored",
         "unrestricted", "amoral", "unethical", "unaligned", "character"),
        atlas=("AML.T0054",),
    ),
    Pattern(
        "developer-mode", "jailbreak mode switch", "high",
        _c(
            r"\b(?:you are|you're|youre)\s+(?:now\s+)?(?:in|running in|operating in)\s+(?:developer|god|jailbreak|"
            r"jailbroken|dan|unrestricted|unfiltered|debug|admin|maintenance|sudo|evil|chaos) mode\b"
            r"|\b(?:chatgpt|gpt|the assistant|an ai|ai|llm|model|assistant)\s+(?:with|in)\s+(?:developer|god|jailbreak|dan)"
            r" mode\b"
            r"|\b(?:developer|jailbreak|dan) mode (?:output|response|enabled\W{0,3}(?:you|chatgpt|gpt))\b"
            r"|\b(?:enable|activate|enter|switch to|turn on|unlock)\s+(?:the\s+)?(?:dan|jailbreak|god|unrestricted|"
            r"unfiltered|uncensored|evil|chaos|opposite) mode\b"
        ),
        ("mode",),
        atlas=("AML.T0054",),
    ),
    Pattern(
        "no-restrictions", "request to drop safety rules", "high",
        _c(
            r"\b(?:you (?:have|has|now have) no |you are (?:free from|not bound by|no longer bound by|unbound by|"
            r"released from|freed from|exempt from) (?:any |all |your )?|(?:answer|respond|reply|act|behave|talk|speak)(?:ing)? "
            r"(?:freely )?without (?:any |all |your )?)(?:restrictions|filters|filtering|guidelines|rules|limits|"
            r"limitations|censorship|ethics|morals|ethical (?:guidelines|constraints|restrictions)|content "
            r"(?:policy|policies|filters?)|safety (?:guidelines|filters?|rules|measures)|boundaries|guardrails)\b"
        ),
        ("restrict", "filter", "guideline", "rules", "limit", "censor", "ethic", "moral", "polic", "safety",
         "boundar", "guardrail"),
        atlas=("AML.T0054",),
    ),
    Pattern(
        "no-restrictions", "request to drop safety rules", "high",
        _c(
            r"\b(?:ai|assistant|model|chatbot|llm|version of (?:yourself|you)|you) (?:with no |without (?:any )?|free of (?:any )?)"
            r"(?:rules|restrictions|filters|guidelines|limits|limitations|ethics|morals|censorship|guardrails|safety "
            r"(?:rules|filters|guidelines))\b"
        ),
        ("with no", "without", "free of"),
        atlas=("AML.T0054",),
    ),
    Pattern(
        "skeleton-key", "Skeleton Key style behaviour update", "high",
        _c(
            r"\bsafe educational context\b|\buncensored outputs?\b|\binstead of refusing\b"
            r"|\b(?:update|augment|change|adjust|modify|expand) your (?:behaviou?r|guidelines|rules) to (?:provide|answer|comply)"
            r"|\b(?:prefix|preface|start|begin|prepend) (?:it|that|the (?:answer|response|output|content)|your "
            r"(?:answer|response|output)) with [\"']?warning\b"
        ),
        ("educational", "uncensored", "refusing", "your behav", "your guideline", "your rules", "warning"),
        atlas=("AML.T0054",),
    ),
    Pattern(
        "fiction-secret", "fiction or role-play used to extract secrets", "medium",
        _c(
            r"\b(?:story|poem|song|script|screenplay|novel|tale|dialogue|roleplay|role-play|fiction|fictional|play|"
            r"rap|lyrics|scene)\b[^.\n]{0,100}\b(?:reveals?|reads? out|tells?|gives?|says|lists?|prints?|recites?|"
            r"spells? out|shares?|leaks?|discloses?|types?)\b[^.\n]{0,60}\b(?:(?:real|actual|your|the|valid|working|"
            r"admin|root) )?(?:api keys?|passwords?|system prompt|secret keys?|credentials|private keys?|access "
            r"tokens?|activation keys?|license keys?|product keys?|windows keys?|serial (?:keys?|numbers?))\b"
            r"|\b(?:grandma|grandmother|granny|babcia|babci)\b[^.\n]{0,120}\b(?:activation keys?|product keys?|"
            r"license keys?|windows (?:10 |11 )?keys?|serial (?:keys?|numbers?)|passwords?|napalm|klucz\w*|hasl\w*)\b"
            r"|\b(?:opowiadani\w*|histori\w*|wiersz\w*|piosenk\w*|scenariusz\w*|bajk\w*|dialog\w*|scenk\w*|"
            r"powiesc\w*|odgrywanie rol)\b[^.\n]{0,100}\b(?:podaje|podal\w*|zdradza|zdradzil\w*|ujawnia|ujawnil\w*|"
            r"mowi|powiedzial\w*|czyta|przeczytal\w*|wypisuje|dyktuje|recytuje|pokazuje|wyswietla|zdradzi|poda)\b"
            r"[^.\n]{0,60}\b(?:klucz\w* api|api key|klucz\w* dostepu|hasl\w*|prompt systemow\w*|token\w*|"
            r"klucz\w* prywatn\w*|dane logowania|numer\w* kart\w*|klucz\w* licencyjn\w*)"
        ),
        ("story", "poem", "song", "script", "novel", "tale", "dialogue", "role", "fiction", "play", "rap", "lyrics",
         "scene", "grand", "babci", "opowiadani", "histori", "wiersz", "piosenk", "scenariusz", "bajk", "dialog",
         "scenk", "powiesc", "odgrywanie"),
        atlas=("AML.T0054",),
    ),
    # ---- tool poisoning and hidden instructions (untrusted content)
    Pattern(
        "tool-poisoning-tag", "hidden instruction block", "high",
        _c(r"<\s*(?:important|instructions?|secret|hidden|hidden[_-]instructions?|note[ _-]to[ _-](?:the[ _-])?"
           r"(?:ai|assistant|model|llm))\s*>"),
        ("<",),
        texts=("raw", "norm"),
        roles=UNTRUSTED_ROLES,
    ),
    Pattern(
        "hidden-from-user", "instruction to hide actions from the user", "high",
        _c(
            r"\b(?:do not|don'?t|dont|never|must not|should not|shouldn'?t)\s+(?:tell|inform|mention|notify|alert|"
            r"show|reveal|disclose|let)\s+(?:this |it |anything |that )?(?:to |about this to |know )?(?:the |your )?"
            r"(?:user|human|end user)\b(?!\s+(?:their|his|her|your)\b)"
            r"|\bwithout (?:telling|informing|notifying|alerting|asking|showing) (?:the |your )?(?:user|human)\b"
            r"|\b(?:the )?user (?:must|should|does) not (?:know|see|notice|be (?:told|informed|aware))"
            r"|\bhide (?:this|it|these|the (?:action|call|step)) from (?:the )?user\b"
            r"|\b(?:do not|don'?t|dont|never) (?:mention|reveal|disclose|acknowledge) (?:this|these) "
            r"(?:instructions?|steps|message|note|tool call)"
            r"|\bnie (?:mow|informuj|wspominaj|pokazuj|zdradzaj)\b[^.\n]{0,20}\buzytkownik\w*"
        ),
        ("user", "human", "hide", "mention", "reveal", "disclose", "uzytkownik"),
        roles=UNTRUSTED_ROLES,
    ),
    Pattern(
        "sensitive-file", "reference to credential files", "high",
        _c(
            r"(?:~/\.ssh\b|\.ssh/(?:id_|authorized_keys|config)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\bmcp\.json\b|"
            r"claude_desktop_config\.json|\.cursor/mcp|\.aws/credentials|(?<![\w.])\.env\b(?!\.example|\.sample|"
            r"\.template|\.dist)|/etc/(?:passwd|shadow)\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|"
            r"\.docker/config\.json|\.kube/config\b|wallet\.dat\b)"
        ),
        (".ssh", "id_", "mcp", "claude_desktop", ".cursor", ".aws", ".env", "/etc/", ".npmrc", ".pypirc", ".netrc",
         ".git-credentials", ".docker", ".kube", "wallet"),
        texts=("raw",),
        roles=frozenset({"tool_definition"}),
    ),
    Pattern(
        "sensitive-file", "instruction to read and send credential files", "high",
        _c(
            r"(?:~/\.ssh\b|\.ssh/(?:id_|authorized_keys)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\bmcp\.json\b|"
            r"claude_desktop_config\.json|\.aws/credentials|(?<![\w.])\.env\b(?!\.example|\.sample|\.template)|"
            r"/etc/(?:passwd|shadow)\b|\.git-credentials\b|\.netrc\b)"
            r"[^\n]{0,120}\b(?:send|upload|post|forward|transmit|exfiltrat\w*|e-?mail|include (?:it|its|the) "
            r"(?:content|contents)|pass (?:it|its|the) (?:content|contents)|as (?:a |the )?(?:parameter|argument)|"
            r"to https?://)"
            r"|\b(?:read|cat|open|load|get|fetch|copy)\b[^\n]{0,40}(?:~/\.ssh\b|\bid_(?:rsa|ed25519)\b(?!\.pub)|"
            r"\.aws/credentials|(?<![\w.])\.env\b(?!\.example)|\bmcp\.json\b)[^\n]{0,120}\b(?:send|upload|post|"
            r"forward|transmit|include|pass|attach|append|paste)\b"
        ),
        (".ssh", "id_", "mcp", "claude_desktop", ".aws", ".env", "/etc/", ".git-credentials", ".netrc"),
        texts=("raw",),
        roles=frozenset({"tool_result"}),
    ),
    Pattern(
        "exfil-instruction", "hidden instruction to send data out", "critical",
        _c(
            rf"\b(?:send|forward|email|e-mail|mail|post|upload|transmit|share|exfiltrate|copy|bcc|cc|leak|submit|"
            rf"deliver|export|wy[sś]lij|prze[sś]lij|przeka[zż]|wyeksportuj|skopiuj)\b[^\n]{{0,100}}?\b{DATA_WORDS}"
            rf"[^\n]{{0,100}}?(?:\bto\b|\binto\b|\bat\b|\bna\b|\bdo\b|:)\s*(?:the )?(?:address |adres |url |endpoint )?"
            rf"(?:{EMAIL}|{URL})"
            rf"|\b(?:send|forward|email|e-mail|mail|post|upload|transmit|bcc|cc|wy[sś]lij|prze[sś]lij)\b[^\n]{{0,30}}?"
            rf"\b(?:to|na|do)\s+(?:{EMAIL}|{URL})[^\n]{{0,100}}?\b{DATA_WORDS}"
        ),
        ("@", "http"),
        texts=("raw",),
        roles=UNTRUSTED_ROLES,
    ),
    Pattern(
        "addressed-to-ai", "instructions addressed to the AI inside content", "medium",
        _c(
            rf"\b(?:if you are|if you're|attention|note to|message (?:to|for)|instructions? (?:to|for)|"
            rf"important for|reminder (?:to|for))\s+(?:an? |the |all |any )?{AI_WORDS}s?\b"
            rf"(?=\s*(?:[:,.!;]|-{{1,2}}\s|\b(?:reading|processing|summari[sz]ing|who|that|you|please|must|should|do|"
            rf"ignore|read|here|only)\b))"
            rf"|\b(?:ai|llm|language model)s?(?: assistants?| agents?| models?)?\s+(?:reading|processing|summari[sz]ing|"
            rf"parsing|browsing|analy[sz]ing) this\b"
        ),
        ("you are", "you're", "attention", "note to", "message", "instruction", "important", "reminder", "ai", "llm",
         "language model"),
        roles=UNTRUSTED_ROLES,
    ),
]


class InjectionHeuristicsControl(Control):
    id = "prompt_injection"
    owasp_llm = ["LLM01"]
    owasp_agentic = ["ASI01"]

    def __init__(self, cfg: PromptInjectionCfg, policy_doc: Any = None) -> None:
        super().__init__(cfg, policy_doc)
        self.roles = frozenset(cfg.apply_to)
        self.enabled = cfg.heuristics.enabled
        self.action = Action.parse(cfg.heuristics.action)

    def applies_to(self, segment: Segment) -> bool:
        return self.enabled and segment.role in self.roles

    def match(self, text: str, role: str = "user") -> list[tuple[Pattern, str]]:
        """Run the patterns on one text (used by tests and eval): returns (pattern, matched text)."""
        norm = normalize_text(text[:MAX_SCAN_CHARS]).replace("_", " ")
        raw = text[:MAX_SCAN_CHARS].casefold()
        out: list[tuple[Pattern, str]] = []
        seen: set[str] = set()
        for p, m, _src in self._iter(norm, raw, role):
            if p.id not in seen:
                seen.add(p.id)
                out.append((p, m.group(0)))
        return out

    def _iter(self, norm: str | None, raw: str | None, role: str):  # noqa: ANN202
        for p in PATTERNS:
            if p.roles is not None and role not in p.roles:
                continue
            for kind in p.texts:
                text = norm if kind == "norm" else raw
                if not text or not any(k in text for k in p.keywords):
                    continue
                for m in p.regex.finditer(text):
                    if p.validate is None or p.validate(m):
                        yield p, m, kind
                        break
                else:
                    continue
                break

    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        if not self.applies_to(segment):
            return []
        role = segment.role
        raw_view = views[0] if views and views[0].kind == "raw" else View(segment.text, "raw")
        raw_text = raw_view.text[:MAX_SCAN_CHARS]
        norm_view = next((v for v in views if v.kind == "normalized"), None)
        norm = norm_view.text if norm_view is not None else " ".join(raw_text.casefold().split())
        if "_" in norm:
            norm = norm.replace("_", " ")  # snake_case smuggling: ignore_all_previous_instructions
        raw_lower = raw_text.casefold()
        exact = len(raw_lower) == len(raw_text)

        findings: list[Finding] = []
        seen: set[str] = set()
        texts: list[tuple[str | None, str | None, str, tuple[int, int] | None]] = [(norm, raw_lower, "raw", None)]
        for v in views[1:]:
            if v.kind.startswith("decoded:"):
                t = v.text[:MAX_SCAN_CHARS]
                texts.append((normalize_text(t).replace("_", " "), t.casefold(), v.kind, v.span))
        for norm_t, raw_t, view_kind, span in texts:
            for p, m, src in self._iter(norm_t, raw_t, role):
                if p.id in seen:
                    continue
                seen.add(p.id)
                fspan = None
                if view_kind == "raw" and src == "raw" and exact:
                    fspan = (m.start(), m.end())
                elif view_kind != "raw":
                    fspan = span
                findings.append(self._finding(segment, p, m.group(0), view_kind if view_kind != "raw" else (
                    "raw" if src == "raw" else "normalized"), fspan))
        return findings

    def _finding(self, segment: Segment, p: Pattern, matched: str, view: str, span: tuple[int, int] | None) -> Finding:
        role = segment.role
        where = {
            "user": "the user message",
            "tool_result": f"the result of tool {segment.tool or segment.source.split(':', 1)[-1]}",
            "tool_definition": f"the definition of tool {segment.tool or segment.source.split(':', 1)[-1]}",
            "system": "the system prompt",
            "tool_call": "tool call arguments",
        }.get(role, segment.source)
        how = ""
        if view.startswith("decoded:"):
            how = f" after decoding ({view.split(':', 1)[1]})"
        elif view == "normalized":
            how = ""
        snippet = " ".join(matched.split())
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        verdict = {
            Action.BLOCK: "the request was blocked",
            Action.REQUIRE_APPROVAL: "the request needs approval",
            Action.REDACT: "the request was flagged",
            Action.LOG: "the request was logged",
            Action.ALLOW: "no action was taken",
        }[self.action]
        if role in UNTRUSTED_ROLES:
            advice = "Treat this source as untrusted; do not let its text steer the agent."
        else:
            advice = "Rephrase the request without instructing the model to drop its rules."
        msg = f"Prompt injection pattern ({p.family}) in {where}{how}: '{snippet}'. {verdict[0].upper()}{verdict[1:]}. {advice}"
        atlas = list(p.atlas) or []
        atlas.insert(0, ATLAS_INDIRECT if role in UNTRUSTED_ROLES else ATLAS_DIRECT)
        agentic = ["ASI01", "ASI06"] if role == "tool_definition" else ["ASI01"]
        return Finding(
            control=self.id,
            rule=f"heuristic.{p.id}",
            severity=p.severity,  # type: ignore[arg-type]
            action=self.action,
            message=msg,
            span=span,
            evidence=snippet,
            owasp_llm=list(self.owasp_llm),
            owasp_agentic=agentic,
            atlas=atlas,
            view=view,
        )
