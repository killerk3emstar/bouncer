# Threat model

Scope: an organization runs AI agents (internal copilots, coding assistants, automations) that call models, MCP tool servers and each other. Bouncer is the checkpoint on those calls. This document lists what we protect, from whom, where the trust boundaries are, which control addresses which threat, and what stays open.

## Assets

| Asset | Example in the demo | Why it matters |
|---|---|---|
| Customer data | CRM records: names, e-mail, PESEL, IBAN, card numbers | Regulatory exposure (GDPR, banking secrecy), fraud |
| Credentials | Cloud keys, tokens, private keys pasted into prompts or returned by tools | Direct compromise of infrastructure |
| Money movement | `payments.create_transfer` | Direct financial loss |
| Outbound channels | `mail.send`, web requests | Exfiltration path |
| System prompts and internal instructions | Copilot system prompt | Reveals controls and business logic |
| Compute budget | Paid API spend, shared local GPU | Denial of wallet, starvation of other teams |
| The control layer itself | Policy file, signature feed, audit log | Tampering disables or hides every other control |

## Actors

- **External content author**: writes a web page, e-mail, document, issue or tool description the agent will read (indirect prompt injection). The most likely attacker; needs no access to our systems.
- **Malicious or careless user** of an agent: direct injection, jailbreak attempts, pasting secrets or PII.
- **Compromised or malicious tool supplier**: an MCP server or package that changes tool definitions after approval (rug pull) or adds hidden behavior (BCC to an outside address).
- **Hijacked agent**: a legitimate agent whose model has been steered by injected content and now issues harmful tool calls.
- **Insider with config access**: can edit the policy or the feed.

## Trust boundaries

1. Agent to Bouncer: the agent authenticates with its own key; it gets only its allowlisted models and tools. An agent acting for another agent (`X-Bouncer-On-Behalf-Of`) must be allowed by `principals.<id>.may_act_for` and gets the intersection of both agents' permissions. The admin API (dashboard, approvals, policy editing) needs a separate admin token; agent keys do not work there, so an agent cannot approve its own held call.
2. Bouncer to model provider: nothing secret or personal crosses unless the policy allows it (redaction happens before forwarding).
3. Tool results back into the model context: everything from `untrusted_source_tools` is untrusted and taints the session.
4. Model output to the agent: tool calls are checked before the agent executes them.
5. Bouncer to judge: only escalations, only redacted text, only to a local host (`judge.allow_external: false` is enforced by the policy schema).
6. Policy and feed into Bouncer: schema-validated policy, ed25519-signed feed.

## Threats and controls

| Threat | Control(s) | Result in Bouncer |
|---|---|---|
| Direct prompt injection, jailbreak phrasing (EN, PL, DE), chat-template tokens, fake system blocks | `prompt_injection` heuristics (T0), T1 classifier, T2 judge; `signatures` (DAN, Skeleton Key, Policy Puppetry, many-shot) | block or require_approval |
| Obfuscated injection (zero-width, Unicode tags, homoglyphs, leetspeak, spaced letters, base64/hex/url, ROT13) | `obfuscation` normalization; every control scans the normalized and decoded views | hidden characters stripped; Unicode tag smuggling blocked |
| Indirect injection in tool results (web page, e-mail, document) | T0/T1/T2 on tool results; session taint; `lethal_trifecta`; T2 goal alignment on side-effect calls | the action is stopped even when the injected text was not recognized |
| Memory poisoning: an agent saves injected instructions to shared memory or a knowledge base, where other sessions read them later | `tool_governance.memory_write_tools` (`kb.write` in the demo): the saved content gets the T0/T1/T2 injection checks before the call reaches the agent; findings tagged ASI06 | block or require_approval |
| An agent acting with another agent's permissions | `X-Bouncer-On-Behalf-Of` allowed only through `principals.<id>.may_act_for`; intersection of models and tools, lower clearance, stricter profile; caller recorded as `via` | 403 `auth.delegation_not_allowed` |
| Exfiltration by e-mail or transfer | `tool_governance.arguments` (recipient domains, forbidden BCC/CC, amount limit), `lethal_trifecta`, T2 exfiltration question, approvals | block or human approval of exactly that call |
| Zero-click exfiltration through rendered markdown (EchoLeak class) | `output_safety.markdown_links` | image/link to a non-allowlisted domain removed |
| Secrets and PII sent to a model provider or returned to an agent | `secrets` (rule set plus entropy), `pii` (checksums: PESEL, NIP, IBAN, Luhn) | redacted before forwarding (a secret in a tool definition blocks the request); card numbers blocked; clearance-aware visibility; the audit log, approvals and the judge only see masked values |
| System prompt leakage | canary token in the system prompt; prompt-leak heuristics | response blocked when the canary appears |
| Tool poisoning and rug pull (MCP) | tool definitions scanned as untrusted text; `mcp_pinning` hash per tool; server allowlist | poisoned or changed definitions blocked until re-approved |
| Known exploit payloads (pickle opcodes, `torch.load`, `trust_remote_code`, unsafe YAML, ShadowRay, Probllama, cloud metadata SSRF, reverse shells) | `signatures` feed, `supply_chain` | block, with CVE and source reference in the finding |
| Excessive agency: calling tools outside the role, actions the user did not ask for | per-principal tool allowlist, `goal_alignment` (T2) | block |
| Runaway agents and denial of wallet | `budgets` (USD/day per team, per session, tokens per minute, GPU seconds), `loops` (identical calls, step limit, breaker) | downgrade to a local model, then 429 |
| Tampering with the control layer | schema validation and last-good-version policy reload with audit of every change; signed feed, and a rollback to an older signed feed version is refused; hash-chained audit log with a head file and `make verify-audit`; admin token for the dashboard API (Authorization header only) | bad policy rejected, bad or older feed rejected, log edits and removed tail lines detectable |

## Failure behavior

- A check that errors or times out follows `defaults.fail_mode` (`closed` blocks, `open` allows and logs). The judge timeout and the judge being down follow the same rule, and the finding says which mode applied.
- An invalid policy never replaces a valid one. An unsigned or tampered feed never replaces a verified one.
- `mode: monitor` exists for shadow rollout; the dashboard shows every control in monitor mode and the posture score counts it as partial.

## Out of scope and residual risk

- **Hallucination and misinformation** (OWASP LLM09): not a control-layer problem; not addressed.
- **Training data and model poisoning** (LLM04): only model-source allowlisting and unsafe deserialization signatures.
- **Vector store access control** (LLM08): retrieved fragments are scanned as untrusted input when they pass through tool results; the store itself is not governed.
- **Agent-to-agent communication** (ASI07, partial): delegation between agents is checked against the policy (`may_act_for`) and the guard API can check any message, but messages between agents are not signed end to end, and the MCP gateway does not accept delegation.
- **Feed key**: the policy names the public key file (`signatures/feed.pub`), it does not pin the key itself. Anyone who can write both the feed and that file can re-sign the feed, so `signatures/` needs the same write protection as the policy (the Docker stack mounts it read-only).
- **Audit log on the gateway host**: the hash chain and the `<audit>.head` sidecar (newest seq and hash) detect edited, deleted, reordered and removed tail lines, but someone who can delete or rewrite both files can drop or rebuild the log. Ship the log to a SIEM so a copy lives elsewhere.
- **Session ids are chosen by the client** (`X-Bouncer-Session`): rotating them evades the per-session limits (`budgets.sessions.max_usd`, `max_steps`, the loop breaker). Sessions are namespaced per agent, so one agent cannot use or pause another agent's session; the per-team limits (USD per day, tokens per minute, GPU seconds per hour) are the hard backstop.
- **Judge capacity is shared**: with `judge.max_concurrency: 1` one agent that triggers many escalations can fill the judge, and the waiting time counts against `judge.timeout_ms`, so other agents' escalations time out and, with `fail_mode: closed`, are blocked. Per-agent judge quotas are not built.
- **In-memory state**: MCP definition pins, approvals, sessions and the scan cache live in process memory and are lost on restart (daily team spend is rebuilt from the audit log); after a restart the next tool definitions seen are pinned again. The MCP server allowlist trusts the name the server reports about itself.
- **PII in tool-call arguments**: tool arguments are never rewritten (redacting an IBAN or a recipient would break a legitimate call), so in arguments only PII entities set to `block` or `require_approval` act; with the shipped policy that is a full card number (`CREDIT_CARD: block`). An IBAN, e-mail address or PESEL in arguments passes unchanged to the agent; it is masked in the audit log, in approvals and in what the judge sees, and recipient domains, amounts, the lethal trifecta and the judge's exfiltration question decide whether the call may send it.
- **Detection limits**: T0 heuristics and signatures miss novel phrasing; T1 is English-only and does not target jailbreaks; T2 quality is measured in `reports/` and is not perfect. The design does not depend on catching every injection: side-effect actions are checked on their own (allowlists, argument rules, trifecta, approvals).
- **Agents that bypass Bouncer**: the control layer only sees traffic sent through it. Network egress rules that force model and tool traffic through the gateway are a deployment requirement.
- **Admin API**: always protected by a bearer token (`BOUNCER_ADMIN_TOKEN`; a random one per run when unset, `off` disables the check) and bound to localhost by default. There is one token for every admin action: a production deployment needs SSO and role separation between policy editors and approvers.
