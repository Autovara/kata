# Deployment

A from-scratch guide to run the full Kata stack on a fresh Ubuntu host: the resident
validator, the dashboard, the pinned Bitsec sandbox, and the model-pinning relay.

This guide is written for a first-time operator. Follow the phases in order.

## What you'll run

| Piece | What it does | Port |
| --- | --- | --- |
| `kata-validator` | Resident validator: webhook intake → PR queue → runs the engine | 8080 |
| `kata-board` | Dashboard (lane state + live status) | 8787 |
| `bitsec_proxy` | Inference proxy: routes agent + scorer traffic to providers | 8087 |
| `kata_model_relay` | Pins the agent model and meters per-PR cost | 8000 (internal) |

## Prerequisites

- Ubuntu host with **Docker**, **[uv](https://docs.astral.sh/uv/)**, and **Node.js**.
- An **OpenRouter** API key (`sk-or-…`) for agent inference.
- A **Chutes** API key (`cpk_…`) for scoring.
- A GitHub token (repo scope) for the competition repo.
- (For public webhooks) an ngrok account, or another reverse proxy.

> **Security:** treat every key as a secret. Never commit a real key or paste it into
> a shared channel. If a key is ever exposed, rotate it before going live.

---

## Read first: two rules that prevent 90% of failures

1. **`INFERENCE_API_KEY` must be an OpenRouter key (`sk-or-…`).** The proxy routes by
   key prefix (`cpk_`→Chutes, `sk-or-`→OpenRouter), and the pinned agent model
   (`qwen/qwen3.6-35b-a3b`) lives on OpenRouter. A Chutes key here makes every agent
   run fail. Only `CHUTES_API_KEY` is the `cpk_` key.
2. **Bring up the Docker infra (network → proxy → relay) before starting the
   validator**, and put `KATA_SN60_INFERENCE_API` in the validator's `.env` file (a
   shell `export` does not reach a systemd service).

---

## Phase 1 — Repos and dependencies

```bash
sudo chown ubuntu:ubuntu /srv && cd /srv

git clone https://github.com/<ORG>/kata.git
git clone https://<GH_TOKEN>@github.com/<ORG>/kata-bot.git
git clone https://github.com/<ORG>/kata-board.git
git clone https://github.com/Bitsec-AI/sandbox.git

# The validator runs as root, so sync the envs it uses as root to keep ownership consistent:
sudo /home/ubuntu/.local/bin/uv sync --directory /srv/kata
sudo /home/ubuntu/.local/bin/uv sync --directory /srv/kata-bot
sudo /home/ubuntu/.local/bin/uv sync --directory /srv/sandbox

cd /srv/kata-board && npm ci && npm run build

mkdir -p /srv/kata-bot/state /srv/kata-bot/work
echo "CHUTES_API_KEY=<CHUTES_KEY>" > /srv/sandbox/.env   # the scorer requires this

sudo git config --global --add safe.directory /srv/kata
sudo git config --global --add safe.directory /srv/sandbox
```

## Phase 2 — Docker infrastructure

```bash
# internal (no-egress) network for untrusted agents
docker network inspect bitsec-net >/dev/null 2>&1 || docker network create --internal bitsec-net

# inference proxy (scorer + agent routing)
cd /srv/sandbox
DOCKER_BUILDKIT=1 docker build -t bitsec-proxy:latest \
  --build-context loggers=/srv/sandbox/loggers validator/proxy
docker rm -f bitsec_proxy 2>/dev/null || true
docker run -d --restart unless-stopped --name bitsec_proxy -p 127.0.0.1:8087:8000 bitsec-proxy:latest
docker network connect bitsec-net bitsec_proxy

# model-pinning relay (built from the kata repo root)
cd /srv/kata
docker build -f deploy/sn60-model-relay/Dockerfile -t kata-sn60-model-relay .
docker rm -f kata_model_relay 2>/dev/null || true
docker run -d --restart unless-stopped --name kata_model_relay --network bitsec-net \
  -e KATA_RELAY_PINNED_MODEL=qwen/qwen3.6-35b-a3b kata-sn60-model-relay

# smoke-test agent image
docker pull ghcr.io/bitsec-ai/<PROJECT>:latest   # if 401: run `docker login ghcr.io` first
```

## Phase 3 — Environment files

`/srv/kata-bot/.env`:

```ini
# webhook intake
KATA_ALLOWED_SOURCE_REPOS=<ORG>/kata
KATA_WEBHOOK_SECRET=<random 32-byte hex: openssl rand -hex 32>
KATA_WEBHOOK_HOST=127.0.0.1
KATA_WEBHOOK_PORT=8080
KATA_WEBHOOK_PATH=/github/webhook
KATA_HEALTH_PATH=/healthz

# what/where it evaluates
KATA_ROOT=/srv/kata
KATA_TARGET_TOKEN=<GH_TOKEN>
KATA_QUEUE_STATE_PATH=/srv/kata-bot/state/queue.json
KATA_LIVE_STATUS_PATH=/srv/kata-bot/state/live-status.json
KATA_WORK_ROOT=/srv/kata-bot/work
KATA_POLL_INTERVAL_SECONDS=5

# SN60 evaluation
KATA_SN60_SANDBOX_ROOT=/srv/sandbox
KATA_SN60_BENCHMARK_FILE=/srv/sandbox/validator/curated-highs-only-2025-08-08.json

# two keys, DIFFERENT providers (see "Read first")
INFERENCE_API_KEY=<OPENROUTER_KEY sk-or-...>
CHUTES_API_KEY=<CHUTES_KEY cpk_...>

# route agent inference through the pinning relay
KATA_SN60_INFERENCE_API=http://kata_model_relay:8000

# start small: one project, one replica
KATA_SN60_PROJECT_KEYS=<PROJECT>
KATA_SN60_REPLICAS_PER_PROJECT=1

# (optional) cost-saving early-stop for many-project runs
# KATA_SN60_EARLY_STOP=1
# KATA_SN60_EARLY_STOP_PHASE1=16
# KATA_SN60_EARLY_STOP_MARGIN=6
```

`/srv/kata-board/.env`:

```ini
PORT=8787
KATA_ROOT=/srv/kata
KATA_QUEUE_STATE_PATH=/srv/kata-bot/state/queue.json
KATA_LIVE_STATUS_PATH=/srv/kata-bot/state/live-status.json
KATA_VALIDATOR_HEALTH_URL=http://127.0.0.1:8080/healthz
KATA_REPO_SLUG=<ORG>/kata
KATA_GITHUB_TOKEN=<GH_TOKEN>
KATA_STATUS_CACHE_TTL_MS=3000
KATA_LEADERBOARD_CACHE_TTL_MS=60000
```

Validate the validator env before starting (this tells you exactly what's missing):

```bash
cd /srv/kata-bot && sudo -E env $(grep -v '^#' .env | xargs) \
  /home/ubuntu/.local/bin/uv run python -m kata_bot check-validator-env
```

## Phase 4 — systemd services

`/etc/systemd/system/kata-validator.service`:

```ini
[Unit]
Description=Kata resident validator
After=network.target docker.service
Requires=docker.service

[Service]
User=root
WorkingDirectory=/srv/kata-bot
EnvironmentFile=/srv/kata-bot/.env
Environment=PATH=/home/ubuntu/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/home/ubuntu/.local/bin/uv run python -m kata_bot serve-validator-env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/kata-board.service`:

```ini
[Unit]
Description=Kata dashboard
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/srv/kata-board
EnvironmentFile=/srv/kata-board/.env
ExecStart=/usr/bin/node server/index.mjs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kata-validator kata-board
curl -s localhost:8080/healthz
curl -s localhost:8787/api/health
```

## Phase 5 — Public tunnel (ngrok)

Expose the validator (8080) and dashboard (8787) with your reverse proxy of choice.
With ngrok, run it as a service, then register the GitHub webhook:

- **Payload URL:** `https://<your-webhook-domain>/github/webhook`
- **Content type:** `application/json`
- **Secret:** the `KATA_WEBHOOK_SECRET` from Phase 3
- **Events:** Pull requests

## Phase 6 — Smoke test

```bash
# reset the cost meter
docker exec kata_model_relay python -c \
  "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8000/costs/reset', method='POST', data=b''))"

# open a submission PR against the competition repo, then watch:
journalctl -u kata-validator -f
watch docker ps

# after it finishes, read the exact agent inference cost:
docker exec kata_model_relay python -c \
  "import urllib.request,json; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8000/costs')), indent=2))"
```

A green smoke test — agent container on `bitsec-net`, nonzero `input_tokens` in
`/costs`, a result comment on the PR, and the dashboard updating — means you are fully
deployed.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Agent runs fail instantly with a model/provider error | `INFERENCE_API_KEY` is not an OpenRouter `sk-or-…` key. |
| Duel refuses to start ("not present in the resolved benchmark") | `KATA_SN60_PROJECT_KEYS` isn't a `project_id` in the benchmark file. |
| `/costs` stays at 0 after a run | `KATA_SN60_INFERENCE_API` missing from `.env`, or the relay isn't on `bitsec-net`. |
| `docker pull ghcr.io/...` returns 401 | Run `docker login ghcr.io`. |
| Validator won't start | Run `check-validator-env` (Phase 3) to see the missing variable. |

## Scaling up

After the smoke test passes, raise `KATA_SN60_PROJECT_KEYS` and set
`KATA_SN60_REPLICAS_PER_PROJECT=3` for full coverage. To control cost at that scale,
enable early-stop (`docs/sn60-early-stop.md`) and track per-PR spend with the relay's
`/costs` endpoint.
