# Archive fuzzing

The `safe_zip_archive` target sends arbitrary bytes through
`automatestig_archive_safety::SafeZipArchive` using intentionally small archive,
entry, name, declared-size, actual-size, ratio, and aggregate-read limits. Every
accepted member is read through a shared `ReadBudget` and an additional narrower
caller limit.

Run a bounded local campaign from the repository root:

```sh
cargo +nightly fuzz run safe_zip_archive fuzz/corpus/safe_zip_archive -- \
  -max_total_time=60 -max_len=4096 -timeout=2 -rss_limit_mb=1024 \
  -dict=fuzz/safe_zip_archive.dict
```

Corpus files prefixed with `hex:` are decoded by the harness. This keeps the
small deterministic ZIP seeds reviewable as text while still exercising raw ZIP
bytes. Inputs without that prefix are passed to the archive reader unchanged.
