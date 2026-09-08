# Athena Agents Roadmap

LLM-driven adversary emulation framework — OPAR loop, tool registry, safety controls, and ground-truth emission.

Aligned with the [100 Days of Underground Nexus](../core-nexus/docs/100-days-challenge.md) challenge.

## Completed

- [x] Core OPAR loop (Observe/Plan/Act/Reflect) with async execution
- [x] Tool registry (TOML-based with capability gates)
- [x] Allowlist verification (SHA-256 integrity checking)
- [x] Rate limiter (token-bucket, per-target)
- [x] Ground-truth emitter (labeled JSONL telemetry)
- [x] Traffic labeling (HTTP headers + env vars for SOC filtering)
- [x] LLM backend interface (Ollama, vLLM, llama.cpp)
- [x] Capability-based access control (profiles declare, gates enforce)
- [x] ICS safety controls (safe-range validation for Modbus writes)
- [x] ICS Modbus TCP crate (read, write, enumerate, fuzz)
- [x] ICS CAN Bus crate (craft, inject, sniff, replay, fuzz)
- [x] `orchestrator/__main__.py` CLI entrypoint for container execution
- [x] ICS eval metrics (coverage, compliance, boundary violations)

## Phase 1: Foundation (Days 1-20)

- [ ] Commit `Cargo.lock` for reproducible Rust builds in Docker
- [ ] First live OPAR scenario against Juice Shop (validate full loop)
- [ ] Verify ground-truth JSONL output is well-formed and parseable by nexus-tui
- [ ] Add `--max-actions` CLI flag to `__main__.py` for quick test runs
- [ ] Add `--dry-run` flag to `__main__.py` (validate config without executing)

## Phase 2: Detection Engineering (Days 21-40)

- [x] Add directory brute-force tool (`dir-bruteforce`, gobuster-style in-process) — Day 23
- [ ] Add tool wrappers for remaining Kali tools (nikto, sqlmap)
- [ ] Add Suricata rule trigger tracking (which actions generate alerts)
- [ ] Emit MITRE ATT&CK technique IDs in ground-truth records
- [ ] Add detection coverage metric (% of actions that triggered SOC alerts)
- [ ] Add session-end summary with technique coverage map

## Phase 3: Agent Intelligence (Days 41-60)

- [ ] Skill loading: read relevant skills from MinIO at Plan phase startup
- [ ] Skill relevance matching (tag-based + filename prefix)
- [ ] Multi-step chain support (sequence objectives, track progress)
- [ ] Chain state tracking (what's achieved, what's next, what failed)
- [ ] Planning quality metrics (actions to objective, dead-end detection)
- [ ] Token usage tracking per scenario (measure skill savings)
- [ ] Model comparison harness (run same scenario with different LLMs, compare)

## Phase 4: Hardening (Days 61-80)

- [ ] **PyO3 integration**: Rewrite performance-critical orchestrator components in Rust with Python bindings
  - Candidate modules: rate limiter, allowlist verifier, ground-truth serializer
  - Keep high-level orchestration in Python for flexibility
  - Expose Rust functions via PyO3 as a native Python extension module
- [ ] **Unified binary option**: Evaluate building a single `athena-agent` binary using PyO3/maturin that embeds Python orchestrator logic with Rust performance paths
- [ ] Add hypothesis property tests for safety control invariants
- [ ] Add integration test suite (mock LLM, real tool execution, verify ground-truth)
- [ ] Add CI workflow (test + lint + type-check on PR)
- [ ] Profile memory usage during long scenarios (identify leaks in action history)

## Phase 5: Advanced (Days 81-100)

- [ ] Multi-agent coordination (shared observation store between OPAR instances)
- [ ] Conflict detection (don't scan same target/port simultaneously)
- [ ] Agent-to-agent communication (findings sharing via MinIO or direct)
- [ ] Scoring engine (automated effectiveness measurement)
- [ ] Challenge scenarios with objective criteria and leaderboard
- [ ] Autonomous skill generation at Reflect phase (write skill to MinIO after novel scenarios)

## Future (Post-Challenge)

### Rust/Python Unification

The long-term direction is to progressively move performance-critical and safety-critical code from Python into Rust while keeping the orchestration layer in Python for rapid iteration:

| Component | Current | Target | Rationale |
|-----------|---------|--------|-----------|
| Rate limiter | Python | Rust (PyO3) | Precise timing, no GIL contention |
| Allowlist verifier | Python | Rust (PyO3) | Crypto-grade hash verification |
| Ground-truth serializer | Python | Rust (PyO3) | High-throughput JSONL emission |
| Tool execution | Python subprocess | Rust native (existing crates) | Already Rust, just need better integration |
| OPAR orchestration | Python async | Python (keep) | Rapid iteration, LLM prompt engineering |
| LLM client | Python httpx | Python (keep) | Simple HTTP, no perf bottleneck |
| Skill loading | Python | Python (keep) | Markdown parsing, template logic |

**PyO3 approach:**
- Use `maturin` for building Python wheels with embedded Rust
- Native extension module importable as `from athena_core import RateLimiter, AllowlistVerifier`
- Keeps `pip install .` workflow intact
- Rust code lives in `crates/athena-pybridge/` alongside existing crates

**RustPython alternative** (evaluated, not recommended):
- RustPython embeds a Python interpreter inside Rust — opposite direction from what we need
- We want Python calling into Rust for hot paths, not Rust hosting Python
- PyO3 is the correct tool for this direction

### Additional Future Work

- WebSocket event streaming (replace file-based ground-truth with live push)
- Distributed execution (run OPAR across multiple containers with shared state)
- Formal verification of safety control invariants (property-based proofs)
- Integration with MITRE CALDERA for technique library and adversary profiles
