#!/usr/bin/env bash
# Helpers partagés par les scripts d'audit.
set -euo pipefail

# Racine du dépôt (ce fichier est dans scripts/lib/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

log()  { printf '\033[0;34m[*]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; }

die() { err "$*"; exit 1; }

# require_cmd <binaire> [message d'aide]
require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Commande requise introuvable : ${cmd}. ${2:-}"
}

# Horodatage UTC pour nommer les sorties.
timestamp() { date -u +%Y%m%dT%H%M%SZ; }
