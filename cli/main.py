"""AEF — Adversary Emulation & C2 Detection Engineering CLI.

Commands
--------
- ``aef server``   : run the live FastAPI C2 listener (or in-process mock).
- ``aef emulate``  : run the full hermetic end-to-end lifecycle and emit
                     telemetry (pure offline, no sockets).
- ``aef validate`` : run the emulation and validate emitted telemetry against
                     the bundled Sigma rules.
- ``aef report``   : generate the ATT&CK coverage Markdown/JSON matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.crypto import RSACipher
from core.listener import build_listener
from core.models import Agent
from core.orchestrator import Campaign, Orchestrator
from detection.matrix_reporter import DetectionMatrix, MatrixReporter
from detection.sigma_engine import SigmaEngine
from detection.telemetry_logger import SyntheticTelemetryLogger

app = typer.Typer(
    name="aef",
    help="Principal-grade adversary emulation and C2 detection engineering.",
    no_args_is_help=True,
)
console = Console()

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = REPO_ROOT / "configs" / "c2_profile.yaml"
DEFAULT_CHAINS = REPO_ROOT / "configs" / "attack_chains.yaml"
DEFAULT_RULES = REPO_ROOT / "detection" / "rules"


def _load_campaign() -> Campaign:
    return Campaign.from_yaml(DEFAULT_CHAINS)


def _fresh_agent() -> Agent:
    return Agent(
        agent_id="agent-aef-0001",
        hostname="SIM-HOST-01",
        user="AEF\\simuser",
        pid=14141,
    )


def _run_hermetic_lifecycle(agent: Agent | None = None) -> Orchestrator:
    """Execute the full offline lifecycle: tasking -> execution -> telemetry."""
    campaign = _load_campaign()
    rsa = RSACipher.generate()
    agent = agent or _fresh_agent()
    telemetry = SyntheticTelemetryLogger(computer=agent.hostname)
    orch = Orchestrator(campaign=campaign, rsa_cipher=rsa, telemetry=telemetry)
    orch.register_agent(agent)
    orch.stage_campaign(agent.agent_id)
    tasks = orch.pending_tasks(agent.agent_id)
    for task in tasks:
        result = orch.exec_module(task.module, agent, task.parameters)
        orch.complete_task(task.task_id, result)
    return orch


def _result_techniques(orch: Orchestrator) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for result in orch.results.values():
        seen.setdefault(result.technique_id, result.module)
    return sorted(seen.items())


@app.command()
def server(
    profile: Path = typer.Option(Path(DEFAULT_PROFILE), "--profile", "-p", exists=True),
    chains: Path = typer.Option(Path(DEFAULT_CHAINS), "--chains", "-c", exists=True),
    mock: bool = typer.Option(
        False, "--mock", help="Run in-process, no listening socket."
    ),
    port: int = typer.Option(8443, "--port"),
) -> None:
    """Start the C2 listener (live uvicorn or hermetic in-process test)."""
    rsa = RSACipher.generate()
    campaign = Campaign.from_yaml(chains)
    fastapi_app = build_listener(
        rsa_cipher=rsa, profile_path=str(profile), campaign=campaign
    )
    if mock:
        console.print(
            Panel(
                "In-process mock listener started (hermetic, no network). "
                "Use `aef emulate` for the offline lifecycle.",
                title="[green]AEF mock listener[/green]",
            )
        )
        orch = _run_hermetic_lifecycle()
        table = Table(title="Mock lifecycle executed")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        for key, value in orch.summary().items():
            table.add_row(str(key), str(value))
        console.print(table)
        return
    import uvicorn

    console.print(f"[green]Starting AEF C2 listener on 127.0.0.1:{port}[/green]")
    uvicorn.run(fastapi_app, host="127.0.0.1", port=port, log_level="info")


@app.command()
def emulate(
    out: Path = typer.Option(Path("telemetry_output"), "--out", "-o"),
) -> None:
    """Run the full offline lifecycle and persist emitted telemetry."""
    orch = _run_hermetic_lifecycle()
    out.mkdir(parents=True, exist_ok=True)
    events_file = out / "telemetry_events.json"
    events_payload = (
        [e.to_eventlog_dict() for e in orch.telemetry.events] if orch.telemetry else []
    )
    events_file.write_text(
        json.dumps(events_payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    table = Table(title="Hermetic emulation summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    for key, value in orch.summary().items():
        table.add_row(str(key), str(value))
    console.print(table)
    console.print(f"[green]Telemetry written to {events_file}[/green]")


@app.command()
def validate(
    out: Path = typer.Option(Path("detection_output"), "--out", "-o"),
) -> None:
    """Run emulation, then validate telemetry against bundled Sigma rules."""
    orch = _run_hermetic_lifecycle()
    engine = SigmaEngine()
    engine.load_directory(DEFAULT_RULES)
    matched: list[str] = []
    table = Table(
        title="Sigma validation", show_header=True, header_style="bold magenta"
    )
    table.add_column("Rule", style="cyan")
    table.add_column("EventID")
    table.add_column("Matched")
    if orch.telemetry is not None:
        for event in orch.telemetry.events:
            for det in engine.detect(event):
                table.add_row(
                    det.rule_title, str(det.event_id), "yes" if det.matched else "no"
                )
                if det.matched:
                    matched.append(det.rule_id)
    console.print(table)
    consolidated = {
        "matches": sorted(set(matched)),
        "rules_loaded": len(engine.rules),
    }
    out.mkdir(parents=True, exist_ok=True)
    target = out / "sigma_validation.json"
    target.write_text(
        json.dumps(consolidated, indent=2, sort_keys=True), encoding="utf-8"
    )
    console.print(f"[green]Validation JSON written to {target}[/green]")


@app.command()
def report(
    fmt: str = typer.Option("md", "--format", "-f", help="md or json"),
    out: Path = typer.Option(Path("coverage_matrix"), "--out", "-o"),
) -> None:
    """Generate the ATT&CK coverage matrix from the last emulation run."""
    orch = _run_hermetic_lifecycle()
    engine = SigmaEngine()
    engine.load_directory(DEFAULT_RULES)
    simulated = _result_techniques(orch)
    matched_rules: dict[str, set[str]] = {}
    events_by_technique: dict[str, int] = {}
    if orch.telemetry is not None:
        for event in orch.telemetry.events:
            if event.technique_id is not None:
                events_by_technique[event.technique_id] = (
                    events_by_technique.get(event.technique_id, 0) + 1
                )
            for det in engine.detect(event):
                if det.matched and event.technique_id is not None:
                    matched_rules.setdefault(event.technique_id, set()).add(det.rule_id)
    reporter = MatrixReporter()
    rule_titles = {r.name: r.title for r in engine.rules}
    matrix: DetectionMatrix
    if fmt == "json":
        matrix = reporter.build(
            simulated, matched_rules, events_by_technique, rule_titles
        )
        output = matrix.to_json()
        suffix = "json"
    else:
        matrix = reporter.build(
            simulated, matched_rules, events_by_technique, rule_titles
        )
        output = reporter.render_markdown(matrix)
        suffix = "md"
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"coverage_matrix.{suffix}"
    target.write_text(output, encoding="utf-8")
    if fmt == "json":
        console.print(matrix.to_json())
    else:
        console.print(output)
    console.print(f"[green]Matrix written to {target}[/green]")


if __name__ == "__main__":
    app()
