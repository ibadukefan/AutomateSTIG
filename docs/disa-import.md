# DISA Import

AutomateSTIG can import DISA STIG content from XCCDF XML files or ZIP archives.

## CLI

```bash
automatestig disa-import --input U_STIG.zip
automatestig disa-import --input U_STIG-xccdf.xml
```

DISA import also generates and persists auto check packs to:

```text
<library>/auto_check_packs/<stig>.json
```

The command reports the number of generated auto checks.

## GUI

Use `Standards` or `Reports` to import a DISA XCCDF XML or ZIP.

`Standards` also includes connected content operations:

- Fetch from DISA.
- Check updates.
- Browse available.

Those operations are opt-in network features.

## API

Upload DISA content with multipart form data:

```bash
curl -H "X-Auth-Token: $AUTOMATESTIG_AUTH_TOKEN" \
  -F "file=@U_STIG.zip" \
  http://127.0.0.1:<PORT>/api/library/import-disa
```

Connected DISA operations:

- `GET /api/disa/available`
- `POST /api/disa/fetch`
- `POST /api/disa/fetch-all`
- `GET /api/disa/check-updates`

## Auto Check Generation

Auto-generation is deterministic and limited to structured check-content that can be mapped safely. Current supported extraction includes Windows registry blocks and Linux sysctl/systemd content.

Manual-review controls remain manual review. Do not treat an imported benchmark as fully automated unless coverage evidence says so.
