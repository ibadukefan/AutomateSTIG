$ErrorActionPreference = 'Stop'

[Console]::Error.WriteLine(@'
AutomateSTIG installation stopped: Windows release binaries are not currently
published or supported. Windows remains in CI for source-portability testing
only. Install AutomateSTIG on a supported macOS or Linux analyst workstation.

No files were downloaded or changed. Do not deploy a source-built Windows
binary for security-sensitive work until the Windows release custody gate is
complete.
'@)
exit 1
