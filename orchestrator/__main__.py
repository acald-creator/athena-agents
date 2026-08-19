"""CLI entrypoint for the OPAR orchestrator.

Invoked via: python3 -m orchestrator --target <name> --config-dir <path>

Loads configuration, verifies safety controls, connects to LLM backend,
and runs the OPAR scenario loop.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="Athena OPAR Agent Orchestrator",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target identifier (matches targets/<name>.toml in config dir)",
    )
    parser.add_argument(
        "--config-dir",
        required=True,
        help="Path to configuration directory",
    )
    return parser.parse_args()


def load_toml(path: Path) -> dict:
    """Load a TOML file. Uses tomllib (3.11+) or tomli as fallback."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    with open(path, "rb") as f:
        return tomllib.load(f)


async def check_llm_health(url: str, retries: int = 3) -> bool:
    """Check LLM backend health with exponential backoff."""
    import httpx

    delay = 1.0
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{url}/api/tags")
                if response.status_code == 200:
                    logger.info("LLM backend healthy at %s", url)
                    return True
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.warning(
                "LLM health check attempt %d/%d failed: %s",
                attempt + 1, retries, e,
            )
            if attempt < retries - 1:
                await asyncio.sleep(delay)
                delay *= 2

    return False


async def run(args: argparse.Namespace) -> int:
    """Main execution: load config, verify safety, run scenario."""
    config_dir = Path(args.config_dir)
    target_name = args.target

    # Load configurations
    tool_registry_path = Path(os.environ.get(
        "ATHENA_TOOL_REGISTRY",
        str(config_dir / "tool-registry.toml"),
    ))
    allowlist_path = Path(os.environ.get(
        "ATHENA_ALLOWLIST",
        str(config_dir / "allowlist.json"),
    ))
    llm_config_path = config_dir / "llm.toml"
    target_config_path = config_dir / "targets" / f"{target_name}.toml"
    allowlist_hash_path = config_dir / "allowlist.sha256"

    # Load LLM config
    llm_config = load_toml(llm_config_path) if llm_config_path.exists() else {}
    ollama_host = os.environ.get("OLLAMA_HOST", llm_config.get("backend", {}).get("url", "http://localhost:11434"))

    # Load target config
    target_config = load_toml(target_config_path)
    logger.info("Loaded target config: %s (host=%s, port=%s)",
                target_name, target_config.get("host"), target_config.get("port"))

    # Verify allowlist integrity
    import hashlib
    import json

    allowlist_data = allowlist_path.read_bytes()
    actual_hash = hashlib.sha256(allowlist_data).hexdigest()
    expected_hash = allowlist_hash_path.read_text().strip()

    if actual_hash != expected_hash:
        logger.error(
            "Allowlist hash mismatch! Expected: %s, Got: %s",
            expected_hash, actual_hash,
        )
        return 1

    allowlist = json.loads(allowlist_data)
    logger.info("Allowlist verified: %d entries", len(allowlist))

    # Verify target is in allowlist
    target_host = target_config.get("host")
    if not any(entry.get("host") == target_host for entry in allowlist):
        logger.error("Target %s not in allowlist", target_host)
        return 1

    # Check LLM backend health
    if not await check_llm_health(ollama_host):
        logger.error("LLM backend unreachable at %s after 3 retries", ollama_host)
        return 1

    # Load capabilities from environment
    capabilities_str = os.environ.get("ATHENA_CAPABILITIES", "")
    capabilities = [c.strip() for c in capabilities_str.split(",") if c.strip()]
    logger.info("Active capabilities: %s", capabilities or ["none"])

    # Load scenario label
    scenario_label = os.environ.get("ATHENA_SCENARIO_LABEL", target_name)

    # Ground-truth output
    gt_output = os.environ.get("ATHENA_GT_OUTPUT", "/opt/athena/output/ground-truth.jsonl")
    logger.info("Ground-truth output: %s", gt_output)

    # --- Run OPAR Loop ---
    from orchestrator.agent import AgentOrchestrator, ScenarioConfig
    from orchestrator.ground_truth import GroundTruthEmitter
    from orchestrator.rate_limiter import RateLimiter
    from orchestrator.tool_registry import ToolRegistry
    from orchestrator.traffic_labeling import TrafficLabeler
    
    # Build components
    tool_registry = ToolRegistry.load(tool_registry_path)

    # Select LLM backend
    backend_type = llm_config.get("backend", {}).get("type", "ollama")
    model_name = llm_config.get("backend", {}).get("model", "llama3:8b")

    if backend_type == "ollama":
        from orchestrator.llm.ollama import OllamaBackend
        llm_backend = OllamaBackend(base_url=ollama_host, model=model_name)
    elif backend_type == "vllm":
        from orchestrator.llm.vllm import VLLMBackend
        llm_backend = VLLMBackend(base_url=ollama_host, model=model_name)
    elif backend_type == "llamacpp":
        from orchestrator.llm.llamacpp import LlamaCppBackend
        llm_backend = LlamaCppBackend(base_url=ollama_host, model=model_name)
    else:
        logger.error("Unknown LLM backend type: %s", backend_type)
        return 1

    # Rate limiter
    rate_config = llm_config.get("rate_limit", {})
    rate_limiter = RateLimiter(
        actions_per_minute=rate_config.get("actions_per_minute", 30),
    )

    # Ground-truth emitter
    # GroundTruthEmitter reads from ATHENA_GT_OUTPUT env var
    ground_truth_emitter = GroundTruthEmitter()

    # Traffic labeler
    traffic_labeler = TrafficLabeler()

    # Scenario config
    scenario = ScenarioConfig(
        target=target_host,
        max_actions=target_config.get("scenario", {}).get("max_actions", 100),
    )

    # Build orchestrator
    orchestrator = AgentOrchestrator(
        tool_registry=tool_registry,
        llm_backend=llm_backend,
        ground_truth_emitter=ground_truth_emitter,
        allowlist_path=allowlist_path,
        allowlist_hash=expected_hash,
        rate_limiter=rate_limiter,
        active_capabilities=capabilities,
        traffic_labeler=traffic_labeler,
        scenario_label=scenario_label,
    )

    # Verify allowlist (redundant but required by the orchestrator API)
    orchestrator.verify_allowlist_integrity()
    orchestrator.validate_target(target_host)

    # Run scenario
    logger.info("Starting OPAR scenario: target=%s, max_actions=%d", target_host, scenario.max_actions)
    start_time = time.time()

    result = await orchestrator.run_scenario(scenario)

    elapsed = time.time() - start_time
    logger.info(
        "Scenario complete: actions=%d, reason=%s, elapsed=%.1fs",
        result.total_actions, result.termination_reason, elapsed,
    )

    # Write final summary record
    import json as json_mod
    summary_record = {
        "scenario_id": result.scenario_id,
        "run_id": result.run_id,
        "total_actions": result.total_actions,
        "termination_reason": result.termination_reason,
        "elapsed_seconds": round(elapsed, 1),
        "label": "scenario_complete",
    }

    gt_path = Path(gt_output)
    gt_path.parent.mkdir(parents=True, exist_ok=True)
    with open(gt_path, "a") as f:
        f.write(json_mod.dumps(summary_record) + "\n")

    return 0 if result.termination_reason in ("completed", "limit-reached") else 1


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    args = parse_args()

    try:
        exit_code = asyncio.run(run(args))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
