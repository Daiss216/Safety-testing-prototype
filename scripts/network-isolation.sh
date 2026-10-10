#!/usr/bin/env bash
# Verify Compose tenant networks. Isolation is Docker network membership
# (see docker-compose.yml), not host iptables — do not DROP FORWARD here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

docker compose ps --status running >/dev/null 2>&1 \
  || fail "stack is not running; start with: docker compose up -d"

cid() {
  local id
  id="$(docker compose ps -q "$1" 2>/dev/null || true)"
  [[ -n "$id" ]] || fail "service '$1' is not running"
  echo "$id"
}

nets_of() {
  docker inspect -f '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}' "$1"
}

# True if the container is attached only to networks whose names end with the
# given suffixes (Compose prefixes the project name).
only_on() {
  local id="$1"
  shift
  local nets got expected
  nets="$(nets_of "$id")"
  [[ -n "${nets// /}" ]] || fail "container $id has no networks"
  got="$(printf '%s\n' $nets | sed 's/.*_//' | sort -u | tr '\n' ' ')"
  expected="$(printf '%s\n' "$@" | sort -u | tr '\n' ' ')"
  [[ "$got" == "$expected" ]]
}

published_ports() {
  docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$1"
}

cannot_reach() {
  local svc="$1" host="$2"
  if docker compose exec -T "$svc" sh -c "command -v getent >/dev/null && getent hosts $host" >/dev/null 2>&1; then
    fail "$svc resolved $host"
  fi
  if docker compose exec -T "$svc" sh -c "command -v ping >/dev/null && ping -c1 -W1 $host" >/dev/null 2>&1; then
    fail "$svc pinged $host"
  fi
  if docker compose exec -T "$svc" sh -c "command -v wget >/dev/null && wget -q -T 2 -O /dev/null http://$host:11434/" >/dev/null 2>&1; then
    fail "$svc reached $host over HTTP"
  fi
  ok "$svc cannot reach $host"
}

FRONT="$(cid frontend)"
BACK="$(cid backend)"
DB="$(cid db)"
LLM="$(cid ollama)"

only_on "$FRONT" edge || fail "frontend must be only on 'edge' (got: $(nets_of "$FRONT"))"
ok "frontend is only on edge"

only_on "$DB" data || fail "db must be only on 'data' (got: $(nets_of "$DB"))"
ok "db is only on data (internal)"

only_on "$LLM" llm || fail "ollama must be only on 'llm' (got: $(nets_of "$LLM"))"
ok "ollama is only on llm"

only_on "$BACK" edge data llm || fail "backend must be on edge+data+llm (got: $(nets_of "$BACK"))"
ok "backend spans edge, data, and llm"

[[ -z "$(published_ports "$LLM")" ]] || fail "ollama must not publish ports (got: $(published_ports "$LLM"))"
ok "ollama publishes no host ports"

[[ -z "$(published_ports "$DB")" ]] || fail "db must not publish ports (got: $(published_ports "$DB"))"
ok "db publishes no host ports"

cannot_reach frontend db
cannot_reach frontend ollama

echo "[bayora] network isolation verified."
