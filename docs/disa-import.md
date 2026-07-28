# DISA Import

AutomateSTIG can import DISA STIG content from XCCDF XML files or ZIP archives.

## CLI

```bash
automatestig disa-import --input U_STIG.zip
automatestig disa-import --input U_STIG-xccdf.xml
```

A ZIP is treated as one import transaction: every selected XCCDF member is
parsed and any eligible generated pack is serialized before the library is
changed. A malformed member, duplicate benchmark ID, storage failure, or ZIP
with no XCCDF members returns nonzero and leaves the batch uncommitted.

## Safety Limits

Local CLI import, GUI upload, and connected DISA download all use the same
fail-closed archive reader:

- 32 MiB maximum compressed ZIP input and 256 entries.
- 16 MiB maximum actual output for one XCCDF member and 64 MiB across selected members.
- 256 MiB maximum declared uncompressed archive size.
- 100:1 declared compression-ratio screen after a 1 MiB grace threshold.
- 16 MiB maximum for a raw XCCDF XML input.

The reader also rejects unsafe or non-UTF-8 paths, duplicate/case-colliding
names, encrypted entries, links and special files, unsupported compression,
and overlapping member regions. Runtime decompression is capped independently
of ZIP metadata using a limit-plus-one probe.

## GUI

Use `Standards` or `Reports` to import a DISA XCCDF XML or ZIP.

`Standards` also includes connected content operations:

- Fetch from DISA.
- Check updates.
- Browse available.

Those operations are opt-in network features.

Connected fetch accepts HTTPS URLs only on the exact DISA host allowlist and
revalidates every redirect. It rejects credentials, non-default ports,
non-`.zip` paths, oversized `Content-Length` values, and streams no more than
32 MiB even when the server omits or lies about that header.

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

Import errors use HTTP status codes as well as the JSON envelope: `400` for a
malformed archive/request, `413` for a resource limit, `415` for an unsupported
upload type, `422` for missing/invalid XCCDF content, `500` for local storage,
and `502` when connected remote content is invalid or oversized.

## Scanner Scope

Importing a benchmark adds content to the local library; it does not create a
new supported scanner. Automated evaluation is limited to the three curated
packs in `content/supported-targets.json`. Other imported benchmarks remain
useful for checklist conversion and review workflows, but are not advertised as
device scanning capability.

Import-time generation is limited to demonstrable Cisco IOS-XE running-config
`config_line` patterns. ONTAP, FreeBSD, and out-of-scope benchmarks generate no
checks; importing a revision that no longer has eligible IOS-XE patterns removes
its stale generated pack transactionally. Generated content does not add a
platform to the supported-target contract.
