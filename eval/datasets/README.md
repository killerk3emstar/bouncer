# Evaluation datasets

JSONL, one object per line:

```json
{"id": "bo-dir-en-001", "text": "...", "label": "injection", "lang": "en", "source": "...", "kind": "direct",
 "channel": "user", "technique": "leetspeak"}
```

| field | values |
|---|---|
| `label` | `injection` (positive class) or `benign` |
| `lang` | `en`, `pl`, `de`, plus a few others in the public set (`es`, `fr`, `hr`, `hi-latn`, `cyrillic`, `other_script`) |
| `kind` | `direct`, `indirect` (instruction hidden in a web page, e-mail, tool result, document or tool description), `jailbreak`, `benign`, `benign_hard` (benign text with trigger words such as "ignore", "override", "system prompt") |
| `channel` | optional; where the text reaches the agent: `user`, `web_page`, `email`, `tool_result`, `tool_definition`, `kb_article`, `crm_note`, `document`, `pull_request`, `chat_transcript` |
| `technique` | optional; obfuscation or jailbreak technique (`spaced_letters`, `leetspeak`, `homoglyphs_cyrillic`, `zero_width`, `base64`, `rot13`, `uppercase`, `fullwidth`, `unicode_tags`, `persona`, `developer_mode`, `many_shot`, ...) |

## Files

| file | rows | injection | benign | source | license |
|---|---|---|---|---|---|
| `bank_ops.jsonl` | 278 | 134 | 144 (60 hard negatives) | written for this project | same as this repository (Apache-2.0) |
| `deepset_train.jsonl` | 546 | 203 | 343 | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), train split | Apache-2.0 (see note) |
| `harmful_requests.jsonl` | 33 | 14 harmful | 19 (defensive and ordinary) | written for this project | same as this repository (Apache-2.0) |
| `deepset_test.jsonl` | 116 | 60 | 56 | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), test split | Apache-2.0 (see note) |

### bank_ops.jsonl (ours)

Written for a bank operations assistant (the demo "Bank Ops Copilot"). Built by
`uv run python eval/datasets/build_bank_ops.py`; edit that script, not the JSONL.

- Benign, 144: English 88 (50 everyday requests and documents, 38 hard negatives), Polish 50 (29
  everyday, 21 hard negatives), German 6 (1 hard negative). Hard negatives use attack-like words in
  normal work ("Ignore the noise in this chart", "How do I rotate AWS access keys", "Explain what a
  pickle file is", "Act as a reviewer for this PR", "Zignoruj poprzedni wykres, policz od nowa").
  12 of the benign rows are documents arriving through tools (vendor page, customer e-mails, KB
  articles, CRM note, JSON tool result), 4 of them hard negatives.
- Attacks, 134: direct (EN 20, PL 12, DE 8), indirect inside tool content (EN 20, PL 8, DE 4),
  jailbreaks (EN 17 incl. 3 many-shot, PL 4, DE 1), and 40 generated obfuscations of 5 base attacks
  (34 EN, 6 PL; counted as `direct`): spaced letters, leetspeak, Cyrillic homoglyphs, zero-width
  characters, base64, ROT13, uppercase, fullwidth, Unicode tag characters.
- All names, accounts, IBAN-like numbers and addresses are fictional. The internal domain is
  `bank.example`; attacker domains use `.test` or `example.net`. Attack goals stay inside the demo
  scenario (leak the system prompt, exfiltrate customer data, skip payment approval); there are no
  requests for real-world harmful content.
- Limits: small (single author, written in one evening), so per-group numbers on a few rows
  (e.g. German, 19 rows) are indicative only. The jailbreaks all target this bank assistant and use
  instruction-override wording; classic long-form jailbreak prompts were not included.

### deepset/prompt-injections

- Downloaded 2026-10-03 with
  `uvx --from huggingface_hub hf download deepset/prompt-injections --repo-type dataset --local-dir <dir>`
  and converted with `uv run --with pyarrow python eval/datasets/convert_deepset.py <dir>`.
- License: the dataset card's YAML header and the Hub API list `apache-2.0`. The same header also
  contains a nested `license: cc-by-4.0` inside `dataset_info`, which is not a standard field; both
  licenses allow redistribution with attribution. We redistribute the converted rows with this
  attribution and the link above.
- Labels are the dataset's own (1 = injection). The dataset does not distinguish injection types,
  so all positives are `kind: direct`. Some labels are debatable (for example role-play requests
  without any instruction override are labeled as injections); we did not relabel anything.
- `lang` is not in the dataset. We assigned it with `bouncer.t1.lang.detect_language`, a German
  marker check for short keyword queries, and 10 manual overrides (see `convert_deepset.py`); the
  short rows were reviewed by hand. 280 of the 662 rows (42%) are German.

### Training-data contamination

The T1 model card
([protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2))
says it was trained on 22 public datasets but names only 7 (`natolambert/xstest-v2-copy`,
`VMware/open-instruct`, `alespalla/chatbot_instruction_prompts`, `HuggingFaceH4/grok-conversation-harmless`,
`Harelix/Prompt-Injection-Mixed-Techniques-2024`, `OpenSafetyLab/Salad-Data`,
`jackhhao/jailbreak-classification`). `deepset/prompt-injections` is not among the named ones. The
card lists five Apache-2.0 datasets by name and deepset is Apache-2.0, which suggests it was not used,
but 15 datasets are unnamed and `Harelix/Prompt-Injection-Mixed-Techniques-2024` has no dataset card,
so contamination cannot be excluded from the card alone. Our measurement points the same way: on its
own evaluation data the model card reports 99.9% recall, while on deepset T1 reaches 37-43% recall at
threshold 0.5. A model that had trained on these rows would be expected to score much higher.
`bank_ops.jsonl` was written after the model was published and cannot be in its training data.
