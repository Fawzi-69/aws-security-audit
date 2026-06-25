#!/usr/bin/env bash
#
# Scanne le Terraform du dépôt avec Checkov et tfsec.
#
# Deux modes selon la cible :
#   - hardened/ et terraform/  -> gate dur : tout finding fait échouer (exit != 0).
#   - insecure/                -> démo : findings attendus, n'échoue jamais (rapport seul).
#
# Sorties JSON écrites dans reports/ pour le rapport consolidé.
#
# Usage : scripts/scan_iac.sh [-o output_dir]
#
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

OUTPUT_DIR="${REPO_ROOT}/reports"
while getopts ":o:h" opt; do
  case "$opt" in
    o) OUTPUT_DIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Option invalide. -h pour l'aide." ;;
  esac
done

require_cmd checkov "Installer : pip install checkov."
require_cmd tfsec "Installer : https://github.com/aquasecurity/tfsec (ou trivy config)."

mkdir -p "$OUTPUT_DIR"
CKV_CONFIG="${REPO_ROOT}/config/checkov/.checkov.yaml"
rc=0

scan_dir() {
  local dir="$1" hard="$2" tag
  tag="$(basename "$dir")"
  log "Scan ${tag} (gate dur : ${hard})"

  # Checkov -> JSON
  checkov -d "$dir" --config-file "$CKV_CONFIG" -o json \
    > "${OUTPUT_DIR}/checkov-${tag}.json" 2> /dev/null || true

  # tfsec -> JSON
  tfsec "$dir" --format json --soft-fail \
    > "${OUTPUT_DIR}/tfsec-${tag}.json" 2> /dev/null || true

  if [ "$hard" = "true" ]; then
    # En gate dur, on relance checkov en mode bloquant pour le code de sortie.
    if ! checkov -d "$dir" --config-file "$CKV_CONFIG" --compact --quiet > /dev/null 2>&1; then
      err "${tag} : findings détectés sur une cible à gate dur."
      rc=1
    else
      ok "${tag} : aucun finding."
    fi
  else
    warn "${tag} : findings attendus (démo), non bloquant."
  fi
}

scan_dir "${REPO_ROOT}/iac/hardened" true
scan_dir "${REPO_ROOT}/terraform/oidc-audit-role" true
scan_dir "${REPO_ROOT}/iac/insecure" false

[ "$rc" -eq 0 ] && ok "Scan IaC terminé." || err "Scan IaC : gate dur en échec."
exit "$rc"
