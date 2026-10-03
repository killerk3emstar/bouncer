"""Supply-chain control (OWASP LLM03, Agentic ASI04).

Looks at code and commands that agents ask tools to run (direction tool_call) and at user input:
- model downloads from sources outside `model_sources_allow` (Hugging Face repo ids in
  from_pretrained / hf_hub_download / snapshot_download / `huggingface-cli download`, `ollama pull`),
- `trust_remote_code=True` (runs Python shipped inside the model repo),
- loading non-safetensors weights (.bin, .pt, .pth, .pkl, .ckpt via torch.load / pickle) when
  `require_safetensors` is set.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from bouncer.core import Action, Control, Finding, ScanContext, Segment, View, mask

HF_LOAD = re.compile(
    r"""(?:from_pretrained|hf_hub_download|snapshot_download|load_dataset|pipeline)\s*\(\s*(?:[a-z_]+\s*=\s*)?["']([A-Za-z0-9][\w.-]*/[\w.-]+)["']"""
)
HF_REPO_ARG = re.compile(r"""repo_id\s*=\s*["']([A-Za-z0-9][\w.-]*/[\w.-]+)["']""")
HF_CLI = re.compile(r"(?:huggingface-cli|\bhf)\W{1,4}download\W{1,4}([A-Za-z0-9][\w.-]*/[\w.-]+)")
HF_URL = re.compile(r"https?://huggingface\.co/([A-Za-z0-9][\w.-]*/[\w.-]+)")
OLLAMA_PULL = re.compile(r"ollama\s+(?:pull|run)\s+([\w./:-]+)|/api/pull[^\n]{0,80}?[\"']name[\"']\s*:\s*[\"']([^\"']+)[\"']")
TRUST_REMOTE = re.compile(r"trust_remote_code\s*=\s*True")
UNSAFE_WEIGHTS = re.compile(r"""["'][^"'\s]+\.(?:bin|pt|pth|pkl|pickle|ckpt)["']""")
UNSAFE_LOAD = re.compile(r"\b(?:torch\.load|pickle\.loads?|joblib\.load|dill\.loads?)\s*\(")


def _allowed(source: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(source, p) or fnmatch.fnmatchcase(source.lower(), p.lower()) for p in patterns)


class SupplyChainControl(Control):
    id = "supply_chain"
    owasp_llm = ["LLM03"]
    owasp_agentic = ["ASI04"]

    def applies_to(self, segment: Segment) -> bool:
        return segment.direction in ("tool_call", "input")

    def scan(self, segment: Segment, views: list[View], ctx: ScanContext) -> list[Finding]:
        cfg: Any = self.cfg
        text = views[0].text if views else segment.text
        # tool-call arguments are JSON strings: unescape quotes so code inside reads naturally
        text = text.replace('\\"', '"').replace("\\n", "\n")
        out: list[Finding] = []
        if segment.direction == "input" and segment.role != "user":
            return out
        sources: list[str] = []
        for rx in (HF_LOAD, HF_REPO_ARG, HF_CLI, HF_URL):
            sources += [f"hf:{m.group(1)}" for m in rx.finditer(text)]
        for m in OLLAMA_PULL.finditer(text):
            name = m.group(1) or m.group(2)
            if name:
                sources.append(f"ollama:{name}")
        for src in dict.fromkeys(sources):
            if cfg.model_sources_allow and not _allowed(src, cfg.model_sources_allow):
                out.append(
                    Finding(
                        control=self.id,
                        rule="model_source_not_allowed",
                        severity="high",
                        action=Action.BLOCK if segment.direction == "tool_call" else Action.LOG,
                        message=f"Model source {src} is not in supply_chain.model_sources_allow {cfg.model_sources_allow}. "
                        "Use an approved model or ask the platform team to vet and allowlist this source.",
                        evidence=src,
                        owasp_llm=list(self.owasp_llm),
                        owasp_agentic=list(self.owasp_agentic),
                    )
                )
        if segment.direction != "tool_call":
            return out
        if cfg.block_trust_remote_code:
            for m in TRUST_REMOTE.finditer(text):
                out.append(
                    Finding(
                        control=self.id,
                        rule="trust_remote_code",
                        severity="critical",
                        action=Action.BLOCK,
                        message="Code sets trust_remote_code=True, which executes Python shipped inside the model repository. "
                        "Remove it and use a model supported natively by the library.",
                        evidence=m.group(0),
                        owasp_llm=list(self.owasp_llm),
                        owasp_agentic=["ASI04", "ASI05"],
                    )
                )
                break
        if cfg.require_safetensors and UNSAFE_LOAD.search(text):
            m = UNSAFE_WEIGHTS.search(text)
            if m:
                out.append(
                    Finding(
                        control=self.id,
                        rule="unsafe_weights_format",
                        severity="high",
                        action=Action.BLOCK,
                        message=f"Code loads pickle-based weights ({mask(m.group(0).strip(chr(39) + chr(34)), 6, 6)}) "
                        "while the policy requires safetensors. Pickle files can execute code on load; convert the "
                        "weights to .safetensors.",
                        evidence=m.group(0)[:80],
                        owasp_llm=list(self.owasp_llm),
                        owasp_agentic=["ASI04", "ASI05"],
                    )
                )
        return out
