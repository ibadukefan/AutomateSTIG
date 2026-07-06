# Remediation

AutomateSTIG generates remediation scripts deterministically from structured checks and open findings.

Available entry points:

- CLI `remediate`.
- Checklist detail `Remediation` action.
- API `GET /api/remediation/{checklist_id}?format=`.

Generated scripts include a "review before applying" header.

## CLI

```bash
automatestig remediate --input server01.ckl --format powershell --output remediate.ps1
automatestig remediate --input server01.ckl --format bash --output remediate.sh
automatestig remediate --input server01.ckl --format ansible --output remediate.yml
```

By default, remediation is generated for open findings. Use `--all` to cover all checks:

```bash
automatestig remediate --input server01.ckl --format ansible --output remediate.yml --all
```

## Supported Mappings

| Check | PowerShell | Bash | Ansible |
| --- | --- | --- | --- |
| `registry` | yes | no | yes |
| `service` | yes | yes | yes |
| `sysctl` | no | yes | yes |
| `package` | no | yes | yes |
| `windows_feature` | yes | no | yes |
| `config_line` | no | yes | yes |
| `file_permission` | no | yes | yes |
| compound `all` | supported through supported child checks | supported through supported child checks | supported through supported child checks |

Findings without a safely derivable fix are reported as manual review. AutomateSTIG does not guess remediation scripts.

## API

```bash
curl -H "X-Auth-Token: $AUTOMATESTIG_AUTH_TOKEN" \
  "http://127.0.0.1:<PORT>/api/remediation/<CHECKLIST_ID>?format=bash"
```

Supported API formats are the same remediation script formats: `powershell`, `bash`, and `ansible`.

## Caveats

Review generated scripts before applying them. Validate in a test environment before production use, especially where service state, package state, system policy, or file permissions can affect availability.
