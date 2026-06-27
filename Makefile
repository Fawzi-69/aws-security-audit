# Audit & durcissement de sécurité AWS.
# Cible : shell POSIX / Linux (runners CI). Lecture seule côté AWS.

SHELL        := /usr/bin/env bash
HARDENED_DIRS := iac/hardened terraform/oidc-audit-role
REGION       ?= eu-west-3
COMPLIANCE   ?= cis_3.0_aws

.DEFAULT_GOAL := help

.PHONY: help deps audit scan-iac tf-validate report sample test clean

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

deps: ## Vérifie la présence des outils requis
	@for c in terraform tflint checkov prowler tfsec python3; do \
		command -v $$c >/dev/null 2>&1 && echo "  ok   $$c" || echo "  MISS $$c"; \
	done

audit: ## Lance l'audit Prowler (CIS) sur le compte AWS courant
	@scripts/run_audit.sh -r $(REGION) -c $(COMPLIANCE)

scan-iac: ## Scanne le Terraform (Checkov + tfsec) ; gate dur sur hardened
	@scripts/scan_iac.sh

tf-validate: ## fmt -check + validate + tflint sur le Terraform durci
	@set -e; for d in $(HARDENED_DIRS); do \
		echo "== $$d =="; \
		terraform fmt -check -recursive $$d; \
		terraform -chdir=$$d init -backend=false -input=false >/dev/null; \
		terraform -chdir=$$d validate; \
		( cd $$d && tflint --init >/dev/null && tflint --no-color ); \
		checkov -d $$d --config-file config/checkov/.checkov.yaml --compact --quiet; \
	done

report: ## Génère le rapport consolidé depuis reports/
	@scripts/generate_report.sh

sample: ## Régénère le rapport d'exemple (synthétique) depuis docs/fixtures
	@python3 scripts/generate_report.py --synthetic \
		--checkov docs/fixtures/checkov-insecure.json \
		--tfsec   docs/fixtures/tfsec-insecure.json \
		--prowler docs/fixtures/prowler.ocsf.json \
		-d docs/fixtures -o reports/sample

test: ## Lance les tests unitaires du générateur de rapport
	@python3 -m unittest discover -s tests -v

clean: ## Supprime les sorties générées (hors sample)
	@find reports -maxdepth 1 -type f -delete 2>/dev/null || true
	@find . -type d -name ".terraform" -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "nettoyé."
