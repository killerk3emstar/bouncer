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

1. Agent to Bouncer: the agent authenticates with its own key; it gets only its allowlisted models and tools.
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
| Exfiltration by e-mail or transfer | `tool_governance.arguments` (recipient domains, forbidden BCC/CC, amount limit), `lethal_trifecta`, T2 exfiltration question, approvals | block or human approval of exactly that call |
| Zero-click exfiltration through rendered markdown (EchoLeak class) | `output_safety.markdown_links` | image/link to a non-allowlisted domain removed |
| Secrets and PII sent to a model provider or returned to an agent | `secrets` (rule set plus entropy), `pii` (checksums: PESEL, NIP, IBAN, Luhn) | redacted before forwarding; card numbers blocked; clearance-aware visibility |
| System prompt leakage | canary token in the system prompt; prompt-leak heuristics | response blocked when the canary appears |
| Tool poisoning and rug pull (MCP) | tool definitions scanned as untrusted text; `mcp_pinning` hash per tool; server allowlist | poisoned or changed definitions blocked until re-approved |
| Known exploit payloads (pickle opcodes, `torch.load`, `trust_remote_code`, unsafe YAML, ShadowRay, Probllama, cloud metadata SSRF, reverse shells) | `signatures` feed, `supply_chain` | block, with CVE and source reference in the finding |
| Excessive agency: calling tools outside the role, actions the user did not ask for | per-principal tool allowlist, `goal_alignment` (T2) | block |
| Runaway agents and denial of wallet | `budgets` (USD/day per team, per session, tokens per minute, GPU seconds), `loops` (identical calls, step limit, breaker) | downgrade to a local model, then 429 |
| Tampering with the control layer | schema validation and last-good-version policy reload with audit of every change; signed feed; hash-chained audit log with `make verify-audit` | bad policy rejected, bad feed rejected, log edits detectable |

## Failure behavior

- A check that errors or times out follows `defaults.fail_mode` (`closed` blocks, `open` allows and logs). The judge timeout and the judge being down follow the same rule, and the finding says which mode applied.
- An invalid policy never replaces a valid one. An unsigned or tampered feed never replaces a verified one.
- `mode: monitor` exists for shadow rollout; the dashboard shows every control in monitor mode and the posture score counts it as partial.

## Out of scope and residual risk

- **Hallucination and misinformation** (OWASP LLM09): not a control-layer problem; not addressed.
- **Training data and model poisoning** (LLM04): only model-source allowlisting and unsafe deserialization signatures.
- **Vector store access control** (LLM08): retrieved fragments are scanned as untrusted input when they pass through tool results; the store itself is not governed.
- **Agent-to-agent identity** (ASI07): the guard API can check any message, but signed delegation between agents is not built.
- **Detection limits**: T0 heuristics and signatures miss novel phrasing; T1 is English-only and does not target jailbreaks; T2 quality is measured in `reports/` and is not perfect. The design does not depend on catching every injection: side-effect actions are checked on their own (allowlists, argument rules, trifecta, approvals).
- **Agents that bypass Bouncer**: the control layer only sees traffic sent through it. Network egress rules that force model and tool traffic through the gateway are a deployment requirement.
- **Admin API**: protected by an optional bearer token (`BOUNCER_ADMIN_TOKEN`) and bound to localhost by default; a production deployment needs SSO and role separation between policy editors and approvers.
