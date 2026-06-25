#!/usr/bin/env bash
#
# Lance Prowler sur le compte AWS courant (checks CIS AWS Benchmark) et écrit
# les résultats dans reports/. Lecture seule — n'effectue aucune modification AWS.
#
# Prérequis : credentials AWS valides dans l'environnement (profil, variables,
# ou rôle assumé via OIDC en CI). Ce script NE crée NI ne stocke de clé.
#
# Usage :
#   scripts/run_audit.sh [-r region] [-c compliance] [-o output_dir]
#
# Exemples :
#   scripts/run_audit.sh
#   scripts/run_audit.sh -r eu-west-3 -c cis_3.0_aws
#
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REGION="${AWS_REGION:-eu-west-3}"
COMPLIANCE="cis_3.0_aws"
OUTPUT_DIR="${REPO_ROOT}/reports"
ALLOWLIST="${REPO_ROOT}/config/prowler/allowlist.yaml"

while getopts ":r:c:o:h" opt; do
  case "$opt" in
    r) REGION="$OPTARG" ;;
    c) COMPLIANCE="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Option invalide. -h pour l'aide." ;;
  esac
done

require_cmd prowler "Installer : pipx install prowler (https://docs.prowler.com)."
require_cmd aws "AWS CLI requise pour vérifier l'identité."

# Garde-fou : refuser de tourner sans identité AWS (évite un run vide silencieux).
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  die "Aucune identité AWS active. Exporter un profil/role avant de lancer l'audit."
fi

mkdir -p "$OUTPUT_DIR"
STAMP="$(timestamp)"
OUT_PREFIX="prowler-${STAMP}"

log "Compte : $(aws sts get-caller-identity --query Account --output text)"
log "Région : ${REGION} | Conformité : ${COMPLIANCE}"
log "Sortie : ${OUTPUT_DIR}/${OUT_PREFIX}.*"

# --status FAIL pour ne remonter que les contrôles en échec dans le rapport.
prowler aws \
  --region "$REGION" \
  --compliance "$COMPLIANCE" \
  --output-formats json-ocsf html csv \
  --output-directory "$OUTPUT_DIR" \
  --output-filename "$OUT_PREFIX" \
  ${ALLOWLIST:+--mutelist-file "$ALLOWLIST"} \
  --no-banner

ok "Audit terminé. JSON OCSF : ${OUTPUT_DIR}/${OUT_PREFIX}.ocsf.json"
ok "Génère le rapport consolidé : make report"
