# ICIT Security Workflows

**Iron City IT Advisors - Automated Security Operations**

This repository contains GitHub Actions workflows for automated security scanning, threat intelligence, and detection validation.

## Quick Start

1. Fork/clone this repository
2. Add required secrets to GitHub (see Configuration below)
3. Update `manifests/targets.txt` with your targets
4. Run workflows from the Actions tab

## Repository Structure

```
icit-security-workflows/
├── .github/workflows/          # GitHub Actions workflows
│   ├── defectdojo-import.yml   # Import scans to DefectDojo
│   ├── epss-update.yml         # Daily EPSS score updates
│   ├── threat-intel-sync.yml   # Threat intelligence pipeline
│   ├── atomic-tests.yml        # Atomic Red Team tests
│   └── dns-audit.yml           # DNS security auditing
├── scripts/                    # Python/PowerShell scripts
├── configs/                    # Configuration files
├── templates/                  # Report templates
└── manifests/                  # Target lists
```

## Workflows

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| EPSS Update | Daily 6am UTC | Download EPSS vulnerability scores |
| Threat Intel | Every 4 hours | Collect IOCs from threat feeds |
| Atomic Tests | Weekly Sunday 3am | Detection validation |
| DNS Audit | Weekly Monday 5am | DNS security assessment |
| DefectDojo Import | Manual | Import scan results |

## GitHub Secrets (Optional)

| Secret | Description |
|--------|-------------|
| FIREBASE_FUNCTION_URL | Dashboard integration |
| DEFECTDOJO_URL | DefectDojo instance |
| DEFECTDOJO_API_KEY | DefectDojo API token |
| MISP_URL | MISP instance |
| MISP_API_KEY | MISP API key |
| WAZUH_API_URL | Wazuh endpoint |
| WAZUH_API_USER | Wazuh username |
| WAZUH_API_PASS | Wazuh password |

## Cost

**$0** - GitHub Actions free tier (2000 mins/month)

---

Iron City IT Advisors - Blue-Collar Security
