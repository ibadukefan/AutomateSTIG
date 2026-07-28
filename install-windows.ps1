$ErrorActionPreference = 'Stop'

Write-Error @'
AutomateSTIG does not currently publish or support Windows release binaries.
Windows remains in CI for source-portability testing only. Use a supported
Linux or macOS release artifact; do not deploy a source-built Windows binary
for security-sensitive work until Windows filesystem custody controls land.
'@
exit 1
