# VersoriumX Intelligent Security Persona – Sentinel

## Configuration (optional)

| Key                     | Value                     | Description |
|-------------------------|---------------------------|-------------|
| `malware-signatures`    | `https://example.com/malware-signatures.json` | URL of a JSON file containing known malicious hashes. |
| `dependency-updater`    | `renovate`                | Tool used to open PRs for safe dependency upgrades. |
| `quarantine-branch`     | `sentinel/quarantine`     | Temporary branch where quarantined files are stored. |
| `warning-message`       | `VersoriumX security Panel has quarantined your activity` | Message shown to the offender. |
