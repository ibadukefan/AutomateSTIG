# Troubleshooting

## Unsigned `.stigpack` Import Fails

Cause: unsigned packs are blocked by default.

Fix for explicit lab-only import:

```bash
AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 automatestig import --pack lab-only.stigpack
```

Preferred fix: import a signed pack and configure trusted keys.

## Trusted Key Missing

Cause: `.stigpack` import requires a trusted Ed25519 public key.

Fix:

1. Place trusted `.pub` files in `~/.automatestig/trusted_keys`, or set `AUTOMATESTIG_TRUSTED_KEYS_DIR`.
2. Re-run verification or import.

```bash
AUTOMATESTIG_TRUSTED_KEYS_DIR=/path/to/trusted_keys automatestig verify --pack content.stigpack
```

## Benchmark Not Found

Cause: the requested `--stig <ID>` is not installed in the local library.

Fix:

```bash
automatestig library list
automatestig disa-import --input U_STIG.zip
automatestig library show <STIG_ID>
```

Then rerun evaluation with the installed benchmark ID.

## Webhook Rejected

Common causes:

- URL is not HTTPS.
- URL includes embedded credentials.
- URL resolves to localhost or a private IP.

Fix the URL or, for an explicit trusted lab deployment, allow private webhook targets:

```bash
AUTOMATESTIG_ALLOW_PRIVATE_WEBHOOKS=1 cargo run --release --bin automatestig-gui
```

## Non-Loopback Server Refuses To Start

Cause: non-loopback binds require `AUTOMATESTIG_AUTH_TOKEN` with at least 16 characters.

Fix:

```bash
AUTOMATESTIG_AUTH_TOKEN=replace-with-16-plus-chars cargo run --release --bin automatestig-gui
```

`/api/status` is unauthenticated. All other `/api/*` routes require the token.

## SSH Connection Fails On Host Key

Cause: SSH rejects unknown host keys by default.

Fix:

- Configure trusted host keys through your SSH environment, or
- Use trust-on-first-use only for explicit enrollment:

```bash
AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1 cargo run --release --bin automatestig-gui
```

## WinRM Plaintext Basic Auth Rejected

Cause: plaintext WinRM Basic auth is blocked by default.

Fix: use HTTPS. For explicit lab-only override:

```bash
AUTOMATESTIG_ALLOW_INSECURE_WINRM=1 cargo run --release --bin automatestig-gui
```

## WinRM TLS Verification Disabled Rejected

Cause: disabling TLS verification is blocked by default.

Fix: use a valid certificate chain. For explicit lab-only override:

```bash
AUTOMATESTIG_ALLOW_INVALID_WINRM_CERTS=1 cargo run --release --bin automatestig-gui
```

## Remote Scan Does Not Produce Expected Results

Remote SSH/WinRM scans require live reachable hosts, valid credentials, network access, and working collectors. WinRM's WS-Man lifecycle is implemented, but success-path validation requires a live Windows listener.
