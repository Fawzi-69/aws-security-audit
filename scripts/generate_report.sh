#!/usr/bin/env bash
#
# Génère le rapport consolidé (findings.json + report.html + remediation.md)
# à partir des sorties présentes dans reports/.
#
# Usage : scripts/generate_report.sh [-d report_dir] [-o output_dir]
#
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPORT_DIR="${REPO_ROOT}/reports"
OUTPUT_DIR=""
while getopts ":d:o:h" opt; do
  case "$opt" in
    d) REPORT_DIR="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Option invalide. -h pour l'aide." ;;
  esac
done

require_cmd python3 "Python 3 requis."

python3 "${REPO_ROOT}/scripts/generate_report.py" \
  -d "$REPORT_DIR" ${OUTPUT_DIR:+-o "$OUTPUT_DIR"}

ok "Rapport généré dans ${OUTPUT_DIR:-$REPORT_DIR}/"
