# adversary-emulation-framework

> Principal-grade adversary emulation and modular C2 orchestration platform —
> automated multi-stage ATT&CK chains, in-memory evasion tradecraft telemetry,
> deterministic Windows event synthesis, and SigmaHQ detection validation.

**Zero network. Fully deterministic. Detection-engineer-tested.**

## License

MIT — Copyright (c) 2026 **Mostafa Ibrahim (DarcHacker)**

## Quickstart

```bash
pip install -r requirements.txt

# Hermetic end-to-end emulation lifecycle (no sockets)
aef --help
aef emulate
aef validate
aef report --format md

# Live listener (uvicorn)
aef server --port 8443

# In-process mock listener
aef server --mock
```

Verify the toolchain:

```bash
make ci          # ruff check . && pytest -v
mypy .
```

## Architecture: C2 Topology

```
                        ┌──────────────────────────────────────────────┐
                        │              AEF C2 LISTENER                  │
                        │  ┌─────────────┐   ┌──────────────────────┐   │
  REGISTER   ──────────▶│  │ /register   │──▶│ Orchestrator         │   │
  (RSA-2048             │  │  handshake  │   │  - agents            │   │
   OAEP)                │  └─────────────┘   │  - task queue (FIFO) │   │
                        │  ┌─────────────┐   │  - campaign state    │   │
  HEARTBEAT ──────────▶│  │ /task       │──▶│  - result store      │   │
  (AES-256-GCM)         │  │  malleable  │   └──────────────────────┘   │
                        │  │  transform  │                              │
  RESULTS  ───────────▶│  │ /result     │──▶ Telemetry logger ──▶ Sigma │
  (AES-256-GCM)         │  └─────────────┘   Engine ──▶ Coverage matrix │
                        └──────────────────────────────────────────────┘
                                  ▲
            async httpx.ASGITransport (hermetic) / uvicorn (live)
                                  │
                        ┌─────────────────────┐
                        │    BEACON (agent)   │
                        │ register → execute  │
                        │ tasks → submit      │
                        └─────────────────────┘
```

### Kill-Chain Pipeline

```
registration → handshake (RSA-2048 OAEP session envelope)
   → tasking (AES-256-GCM heartbeats with jitter & malleable headers)
   → execution (BaseModule units)
   → telemetry (synthetic Windows Security / Sysmon events 1,3,7,8,10,11,13,4698)
   → detection validation (native Sigma engine)
   → coverage matrix (markdown / json)
```

## Dual-Layer Transport Crypto

| Layer | Algorithm | Purpose |
|---|---|---|
| Handshake | RSA-2048 OAEP (SHA-256) | Wrap ephemeral AES-256 session key |
| Transport | AES-256-GCM (authenticated) | Beacon heartbeats & task delivery |

The malleable profile (`configs/c2_profile.yaml`) drives jitter %, injected
headers, junk-byte padding, and base64 payload shaping.

## Module & ATT&CK Coverage

| Technique ID | Technique | Tactic | Module |
|---|---|---|---|
| T1082 | System Information Discovery | Discovery | `system_profile` |
| T1087 | Account Discovery | Discovery | `user_enum` |
| T1049 | Network Connection Discovery | Discovery | `network_connections` |
| T1003.001 | LSASS Memory | Credential Access | `lsass_dump_access` |
| T1003.001 | OS Credential Dumping (DPAPI) | Credential Access | `dpapi_query` |
| T1047 | Windows Management Instrumentation | Lateral Movement | `wmiprvse_dispatch` |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | `smb_admin_share` |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | `registry_runkey` |
| T1053.005 | Scheduled Task | Persistence | `scheduled_task` |
| T1562.001 | Impair Defenses (AMSI) | Defense Evasion | `amsi_patch_sim` |
| T1055 | Process Injection (Hollowing) | Defense Evasion | `process_hollowing_telemetry` |

Every module inherits `BaseModule` and implements `validate`, `execute`,
`rollback`, and telemetry emission. Persistence modules carry automatic,
idempotent rollback routines. **No module touches real process memory,
registry, filesystem state, or any network socket.**

## Telemetry Engine

The synthetic telemetry generator writes events matching Microsoft Event XML /
JSON schema shapes:

- **Sysmon Event 1** — ProcessCreate
- **Sysmon Event 3** — NetworkConnect
- **Sysmon Event 7** — ImageLoad
- **Sysmon Event 8** — CreateRemoteThread
- **Sysmon Event 10** — ProcessAccess (genuine access masks `0x1010` / `0x1438`)
- **Sysmon Event 11** — FileCreate
- **Sysmon Event 13** — RegistryValueSet
- **Security 4698** — ScheduledTaskCreated

## Sigma Engine

Native YAML rule parser supporting:

- field modifiers: `contains`, `startswith`, `endswith`, `re`, `exists`,
  `cased`, `base64offset`, `utf16*`
- conditions: `selection and not filter`, `selection or other`,
  `1 of selection_*`, `all of them`, parentheses, `not`
- array values with OR semantics, glob `*`/`?` wildcards

Bundled rules in `detection/rules/`:
`proc_creation_wmi.yaml`, `lsass_access_memory.yaml`,
`registry_run_persistence.yaml`.

## Directory Layout

```
adversary-emulation-framework/
├── configs/          # malleable C2 profile + attack-chain playbook
├── core/             # crypto, models, FastAPI listener, orchestrator
├── modules/          # safe ATT&CK execution units +
├── agent/            # beacon lifecycle + sandbox executor
├── detection/        # telemetry logger, Sigma engine, coverage matrix, rules
├── cli/              # Typer CLI (server / emulate / validate / report)
└── tests/            # pytest suite (crypto, modules, C2 pipeline, telemetry, detection)
```

## Hermetic Operation

All commands support fully offline operation:

```
aef emulate     # executes the complete campaign locally, writes JSON telemetry
aef validate    # runs emulation, then reports Sigma match coverage
aef report      # writes coverage_matrix.md / .json
aef server --mock  # in-process ASGI listener, no socket
```

## Authorized Use

This framework is a **simulation and detection-validation** platform for use
only on systems you own or have explicit written authorization to test.
See [`DISCLAIMER.md`](DISCLAIMER.md).