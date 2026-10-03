# Bouncer: common commands. Everything runs through uv (Python 3.12).
SHELL := /bin/bash
UV ?= uv
PY := $(UV) run python

.PHONY: help setup models dev gateway mock mcp feed judge judge-fake test test-live eval eval-full bench demo verify-audit sign-feed lint docker-build docker-up docker-down docker-test clean-data

help:
	@echo "make setup         install dependencies (uv sync) and create .env from .env.example"
	@echo "make models        download T1 (ONNX), the Clef MLX judge and the Ollama models"
	@echo "make dev           gateway :8700 + simulated upstream :8702 + demo MCP :8703 + feed server :8704"
	@echo "make judge         T2 judge service :8701 (Clef MLX on Apple Silicon; JUDGE_BACKEND=ollama-guard|fake)"
	@echo "make test          offline test suite (no network, no models), reports in reports/tests/"
	@echo "make test-live     the same cases against the running stack with real T1/T2"
	@echo "make eval          detection quality of T0 and T1 (no judge needed), reports/eval_quick.md"
	@echo "make eval-full     T0, T1 and the full pipeline with the T2 judge (needs make judge), reports/eval_layers.md"
	@echo "make bench         gateway latency overhead, reports/bench.md"
	@echo "make demo          scripted Bank Ops Copilot scenarios against the running stack"
	@echo "make verify-audit  check the audit log hash chain"
	@echo "make sign-feed     sign signatures/feed.json (creates a dev key on first use)"

setup:
	$(UV) sync
	@test -f .env || cp .env.example .env
	@mkdir -p data reports/tests

models:
	uvx --from huggingface_hub hf download protectai/deberta-v3-base-prompt-injection-v2 --include "onnx/*" --local-dir models/deberta-pi-v2
	uvx --from huggingface_hub hf download TrevorJS/clef-flash-mlx-4bit --local-dir models/clef-flash-mlx-4bit
	ollama pull llama-guard3:1b
	ollama pull qwen3:8b

dev:
	$(PY) scripts/dev.py

gateway:
	$(PY) -m bouncer.gateway.app

mock:
	$(PY) -m demo.mock_upstream

mcp:
	$(PY) -m demo.mcp_server

feed:
	$(PY) scripts/feed_server.py

judge:
	JUDGE_BACKEND=$${JUDGE_BACKEND:-clef-mlx} $(PY) -m judge.server

judge-fake:
	JUDGE_BACKEND=fake $(PY) -m judge.server

test:
	@mkdir -p reports/tests
	$(UV) run pytest -m "not live" --junitxml=reports/tests/junit.xml --html=reports/tests/report.html --self-contained-html
	@cat reports/tests/summary.md

test-live:
	$(UV) run pytest -m live tests/live -v

eval:
	$(PY) eval/run_eval.py --layers t1,eval.layers:t0 --datasets bank_ops,deepset_test --out eval_quick

eval-full:
	$(PY) eval/run_eval.py --layers t1,eval.layers:t0,eval.layers:pipeline,eval.layers:pipeline_tool_result --datasets bank_ops,deepset_test --out eval_layers

bench:
	$(PY) scripts/bench.py

demo:
	$(PY) -m demo.agent --mode scripted --all

verify-audit:
	$(PY) scripts/verify_audit.py $${AUDIT:-data/audit.jsonl}

sign-feed:
	$(PY) scripts/sign_feed.py

lint:
	$(UV) run ruff check bouncer judge demo scripts tests

docker-build:
	docker compose build

docker-up:
	docker compose up -d gateway mock mcp feed

docker-down:
	docker compose down

docker-test:
	docker compose run --rm tests

clean-data:
	rm -f data/audit.jsonl
