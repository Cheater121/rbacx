# OpenFGA + RBACX Demo

This folder contains a minimal demo to verify the `OpenFGAChecker` inside your RBACX build.

## Prerequisites

- Docker Desktop (or Docker Engine on Linux) with Compose V2.
- Python environment with `rbacx[rebac-openfga]` installed.

## Start OpenFGA and import the demo store

```powershell
# 1) Start the OpenFGA server
docker compose -f .\docker-compose.yml up -d openfga

# 2) Import the demo store (model + tuples from store.fga.yaml)
docker compose -f .\docker-compose.yml run --rm fga-import
```

## Get the store ID

```powershell
docker compose -f .\docker-compose.yml run --rm fga-import store list
```

Copy the store ID from the output and set it as an environment variable:

```powershell
$env:OPENFGA_STORE_ID = "PUT_STORE_ID_HERE"
```

Optionally pin a specific authorization model version:

```powershell
$env:OPENFGA_MODEL_ID = "PUT_MODEL_ID_HERE"
```

## Run the demo

```powershell
python demo_openfga.py
# Expected output:
# Allowed: True
```

## What the demo checks

The policy requires the `viewer` relation between the subject and the resource
(evaluated via OpenFGA). The demo store ships with this tuple pre-loaded:

```
user:alice  viewer  clip:clip1
```

So `alice` reading `clip1` with action `clip.read` should be **allowed**.

## Troubleshooting

If the output is `Allowed: False`, open the Playground at `http://localhost:3000`
and verify:

- The model contains a `clip` type with a `viewer` relation.
- The tuple `user:alice viewer clip:clip1` exists (directly or transitively via
  the parent chain `camera → site → group`).

To write a tuple manually using the CLI:

```powershell
docker compose -f .\docker-compose.yml run --rm fga-import tuple write `
  --store-id $env:OPENFGA_STORE_ID `
  user:alice viewer clip:clip1
```

> **Note:** argument order for tuple commands is always `user relation object`.
> For example: `user:alice viewer clip:clip1`.
> Passing them in a different order will cause a parsing error.
