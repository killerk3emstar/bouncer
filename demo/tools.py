"""Bank Ops Copilot tools: implementations and OpenAI tool schemas.

All tools run on fake data and have no external effects:
- crm.lookup_customer   reads the synthetic customer table (demo/data.py)
- kb.search             searches the fictional internal knowledge base
- web.fetch             no network; serves files from demo/web/<host>/<path>.html
- mail.send             appends to an in-memory outbox, sends nothing
- payments.create_transfer  records a simulated transfer, moves no money
- code.run_python       never executes anything

Names: the policy uses dotted names (crm.lookup_customer). On the OpenAI wire the
dots become "__" (crm__lookup_customer); see demo/naming.py. ``run_tool`` accepts
either form. Tool results are JSON strings (or plain text for web.fetch), which is
what the agent puts into the ``tool`` message.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from demo import data
from demo.naming import to_policy_name, to_wire_name

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_FETCH_CHARS = 20_000
MAX_CUSTOMER_MATCHES = 10
SUPPORTED_CURRENCIES = {"PLN", "EUR", "USD", "GBP", "CHF"}


class ToolError(Exception):
    """Invalid arguments or an unknown tool. The message goes back to the model."""


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Mutable demo state (outbox and transfers); reset between scenarios
# ---------------------------------------------------------------------------

OUTBOX: list[dict[str, Any]] = []
TRANSFERS: list[dict[str, Any]] = []
_message_ids = itertools.count(1)
_transfer_ids = itertools.count(1)


def reset_state() -> None:
    global _message_ids, _transfer_ids
    OUTBOX.clear()
    TRANSFERS.clear()
    _message_ids = itertools.count(1)
    _transfer_ids = itertools.count(1)


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


def _fold(text: str) -> str:
    return data.ascii_fold(text).lower()


def crm_lookup_customer(query: str) -> str:
    q = (query or "").strip()
    if not q:
        raise ToolError("query is empty; pass a customer ID (C-10001), a name, an e-mail, a phone or an IBAN")
    customers = data.get_customers()
    if q in {"*", "all"}:
        matches = list(customers)
    else:
        exact = data.get_customer(q)
        if exact:
            matches = [exact]
        else:
            fq = _fold(q)
            digits = re.sub(r"\D", "", q)
            matches = [
                c
                for c in customers
                if fq in _fold(c.name)
                or fq in c.email.lower()
                or fq.replace(" ", "") in c.iban.lower()
                or (len(digits) >= 6 and digits in re.sub(r"\D", "", c.phone))
            ]
    returned = matches[:MAX_CUSTOMER_MATCHES]
    result: dict[str, Any] = {
        "total_matches": len(matches),
        "returned": len(returned),
        "customers": [c.to_dict() for c in returned],
    }
    if len(matches) > len(returned):
        result["note"] = f"Showing the first {len(returned)} of {len(matches)} matches."
    return _json(result)


_WORD = re.compile(r"[a-z0-9]+")


def kb_search(query: str) -> str:
    terms = [t for t in _WORD.findall(_fold(query or "")) if len(t) >= 3]
    if not terms:
        raise ToolError("query needs at least one word of 3 or more characters")
    scored = []
    for article in data.get_kb():
        title = _fold(article.title)
        tags = " ".join(article.tags)
        body = _fold(article.body)
        score = sum(3 * title.count(t) + 2 * tags.count(t) + body.count(t) for t in terms)
        if score:
            scored.append((score, article))
    scored.sort(key=lambda pair: (-pair[0], pair[1].id))
    results = [
        {"id": a.id, "title": a.title, "classification": a.classification, "text": a.body}
        for _, a in scored[:3]
    ]
    return _json({"query": query, "results": results})


def _resolve_web_path(url: str) -> Path | None:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"}:
        raise ToolError("only http:// and https:// URLs are supported")
    host = (parts.hostname or "").lower().removeprefix("www.")
    if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ToolError(f"invalid host in URL: {url}")
    path = unquote(parts.path).strip("/") or "index"
    if not path.endswith(".html"):
        path += ".html"
    web_root = WEB_ROOT.resolve()
    host_root = (web_root / host).resolve()
    if host_root.parent != web_root:
        return None
    candidate = (host_root / path).resolve()
    if not candidate.is_relative_to(host_root) or not candidate.is_file():
        return None
    return candidate


def web_fetch(url: str) -> str:
    target = _resolve_web_path(url)
    if target is None:
        return f"HTTP 404 Not Found: {url} (the demo runs offline; only pages under demo/web/ exist)"
    content = target.read_text(encoding="utf-8")
    if len(content) > MAX_FETCH_CHARS:
        content = content[:MAX_FETCH_CHARS] + "\n[truncated]"
    return content


def _split_addresses(value: str | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [a.strip() for a in re.split(r"[,;]", str(value)) if a.strip()]


def mail_send(to: str, subject: str, body: str, cc: str | None = None, bcc: str | None = None) -> str:
    recipients = _split_addresses(to)
    if not recipients:
        raise ToolError("'to' needs at least one e-mail address")
    message_id = f"msg_{next(_message_ids):04d}"
    OUTBOX.append(
        {
            "id": message_id,
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "to": recipients,
            "cc": _split_addresses(cc),
            "bcc": _split_addresses(bcc),
            "subject": subject,
            "body": body,
        }
    )
    return _json({"status": "queued", "message_id": message_id, "note": "Demo outbox only; no e-mail was sent."})


def payments_create_transfer(from_account: str, to_iban: str, amount: float, currency: str, title: str) -> str:
    try:
        value = round(float(amount), 2)
    except (TypeError, ValueError) as exc:
        raise ToolError(f"amount must be a number, got {amount!r}") from exc
    if value <= 0:
        raise ToolError("amount must be greater than 0")
    cur = (currency or "").upper()
    if cur not in SUPPORTED_CURRENCIES:
        raise ToolError(f"unsupported currency {currency!r}; use one of {sorted(SUPPORTED_CURRENCIES)}")
    if not data.iban_is_valid(to_iban or ""):
        raise ToolError(f"to_iban {to_iban!r} is not a valid IBAN (checksum failed)")
    transfer_id = f"TRF-{next(_transfer_ids):06d}"
    TRANSFERS.append(
        {
            "id": transfer_id,
            "from_account": from_account,
            "to_iban": to_iban.replace(" ", ""),
            "amount": value,
            "currency": cur,
            "title": title,
        }
    )
    return _json(
        {"status": "created", "transfer_id": transfer_id, "amount": value, "currency": cur,
         "note": "Simulated transfer; no money moved."}
    )


def code_run_python(code: str) -> str:
    return _json(
        {"status": "not_executed", "chars": len(code or ""),
         "note": "sandbox disabled in demo: the code was not executed."}
    )


# ---------------------------------------------------------------------------
# Registry and OpenAI schemas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    name: str  # policy name, e.g. crm.lookup_customer
    description: str
    parameters: dict[str, Any]  # JSON schema of the arguments
    func: Callable[..., str]

    @property
    def wire_name(self) -> str:
        return to_wire_name(self.name)

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.wire_name, "description": self.description, "parameters": self.parameters},
        }


def _schema(properties: dict[str, dict[str, Any]], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in [
        ToolSpec(
            "crm.lookup_customer",
            "Look up Example Bank customers in the CRM. Returns contact details, PESEL, IBAN, balance, "
            "segment and KYC status. Use * to list customers (first 10).",
            _schema({"query": {"type": "string", "description": "Customer ID (C-10001), name, e-mail, phone or IBAN."}},
                    ["query"]),
            crm_lookup_customer,
        ),
        ToolSpec(
            "kb.search",
            "Search the internal knowledge base (fees, limits, KYC, security procedures). Returns up to 3 articles.",
            _schema({"query": {"type": "string", "description": "Search words."}}, ["query"]),
            kb_search,
        ),
        ToolSpec(
            "web.fetch",
            "Fetch a web page and return its HTML. Third-party content.",
            _schema({"url": {"type": "string", "description": "http(s) URL."}}, ["url"]),
            web_fetch,
        ),
        ToolSpec(
            "mail.send",
            "Send an e-mail from the operations mailbox.",
            _schema(
                {
                    "to": {"type": "string", "description": "Recipient address(es), comma-separated."},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "cc": {"type": "string", "description": "Optional copy recipients, comma-separated."},
                    "bcc": {"type": "string", "description": "Optional hidden copy recipients, comma-separated."},
                },
                ["to", "subject", "body"],
            ),
            mail_send,
        ),
        ToolSpec(
            "payments.create_transfer",
            "Create a bank transfer from an Example Bank account.",
            _schema(
                {
                    "from_account": {"type": "string", "description": "Debit account IBAN."},
                    "to_iban": {"type": "string", "description": "Beneficiary IBAN."},
                    "amount": {"type": "number", "description": "Amount, greater than 0."},
                    "currency": {"type": "string", "description": "PLN, EUR, USD, GBP or CHF."},
                    "title": {"type": "string", "description": "Transfer title."},
                },
                ["from_account", "to_iban", "amount", "currency", "title"],
            ),
            payments_create_transfer,
        ),
        ToolSpec(
            "code.run_python",
            "Run a Python snippet in the analytics sandbox and return its output.",
            _schema({"code": {"type": "string", "description": "Python source code."}}, ["code"]),
            code_run_python,
        ),
    ]
}

TOOL_NAMES: tuple[str, ...] = tuple(TOOLS)


def get_tool(name: str) -> ToolSpec:
    spec = TOOLS.get(to_policy_name(name))
    if spec is None:
        raise ToolError(f"unknown tool {name!r}; known tools: {', '.join(TOOL_NAMES)}")
    return spec


def openai_tools(names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """OpenAI ``tools`` array for the given tool names (policy or wire form); all tools by default."""
    selected = TOOL_NAMES if names is None else [get_tool(n).name for n in names]
    return [TOOLS[n].openai_schema() for n in selected]


def run_tool(name: str, arguments: dict[str, Any] | str | None) -> str:
    """Run a tool by policy or wire name. Errors are returned as text so the agent loop continues."""
    try:
        spec = get_tool(name)
        if isinstance(arguments, str):
            arguments = json.loads(arguments) if arguments.strip() else {}
        if not isinstance(arguments, dict):
            raise ToolError("arguments must be a JSON object")
        allowed = set(spec.parameters["properties"])
        unknown = set(arguments) - allowed
        if unknown:
            raise ToolError(f"unexpected argument(s) for {spec.name}: {', '.join(sorted(unknown))}")
        missing = [p for p in spec.parameters["required"] if p not in arguments]
        if missing:
            raise ToolError(f"missing argument(s) for {spec.name}: {', '.join(missing)}")
        return spec.func(**arguments)
    except ToolError as exc:
        return _json({"error": str(exc)})
    except json.JSONDecodeError as exc:
        return _json({"error": f"arguments are not valid JSON: {exc}"})
