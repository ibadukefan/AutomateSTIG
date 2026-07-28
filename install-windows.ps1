$ErrorActionPreference = 'Stop'

$Repo = 'ibadukefan/AutomateSTIG'
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$TempDir = $null

function Fail {
    param([string]$Message)
    throw $Message
}

try {
    try {
        $Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $Arch = $env:PROCESSOR_ARCHITECTURE
    }

    switch -Regex ($Arch) {
        '^(X64|Amd64)$' {
            $Target = 'x86_64-pc-windows-msvc'
            break
        }
        '^(Arm64|Arm)$' {
            Fail 'No prebuilt Windows arm64 archive is available yet; build AutomateSTIG from source.'
        }
        default {
            Fail "Unsupported Windows architecture: $Arch"
        }
    }

    if ($env:AUTOMATESTIG_VERSION) {
        $Tag = $env:AUTOMATESTIG_VERSION
    } else {
        Write-Host 'Resolving latest AutomateSTIG release...'
        $Latest = Invoke-RestMethod -Uri $ApiUrl -Headers @{ 'User-Agent' = 'AutomateSTIG installer' }
        $Tag = $Latest.tag_name
    }

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        Fail 'Could not determine release tag.'
    }
    if ($Tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        Fail "Invalid release tag: $Tag"
    }

    $Cosign = Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue
    if (-not $Cosign) {
        Fail 'Required command not found: cosign. Install cosign from https://docs.sigstore.dev/cosign/system_config/installation/.'
    }

    $ArchiveName = "automatestig-$Tag-$Target.zip"
    $ChecksumName = "$ArchiveName.sha256"
    $BundleName = "$ArchiveName.sigstore.bundle"
    $DownloadBase = "https://github.com/$Repo/releases/download/$Tag"
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("automatestig-" + [guid]::NewGuid().ToString('N'))
    $ExtractDir = Join-Path $TempDir 'extract'
    $ArchivePath = Join-Path $TempDir $ArchiveName
    $ChecksumPath = Join-Path $TempDir $ChecksumName
    $BundlePath = Join-Path $TempDir $BundleName

    New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null

    Write-Host "Downloading AutomateSTIG $Tag for $Target..."
    Invoke-WebRequest -Uri "$DownloadBase/$ArchiveName" -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri "$DownloadBase/$ChecksumName" -OutFile $ChecksumPath -UseBasicParsing
    Invoke-WebRequest -Uri "$DownloadBase/$BundleName" -OutFile $BundlePath -UseBasicParsing

    Write-Host 'Verifying SHA-256 checksum...'
    $ChecksumLines = @(Get-Content -Path $ChecksumPath | Where-Object { $_.Trim().Length -gt 0 })
    if ($ChecksumLines.Count -ne 1) {
        Fail "$ChecksumName must contain exactly one checksum record."
    }
    $ChecksumParts = @($ChecksumLines[0].Trim() -split '\s+')
    if ($ChecksumParts.Count -ne 2 -or $ChecksumParts[0] -notmatch '^[0-9A-Fa-f]{64}$') {
        Fail "$ChecksumName contains an invalid checksum record."
    }
    if ($ChecksumParts[1] -cne $ArchiveName) {
        Fail "$ChecksumName does not name $ArchiveName."
    }

    $ExpectedHash = $ChecksumParts[0].ToUpperInvariant()
    $ActualHash = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToUpperInvariant()
    if ($ExpectedHash -ne $ActualHash) {
        Fail "Checksum verification failed for $ArchiveName."
    }

    Write-Host 'Verifying keyless Sigstore signature...'
    $Identity = "https://github.com/$Repo/.github/workflows/ci.yml@refs/tags/$Tag"
    $env:COSIGN_EXPERIMENTAL = '1'
    & $Cosign.Path verify-blob `
        --bundle $BundlePath `
        --certificate-identity $Identity `
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
        $ArchivePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "Sigstore verification failed for $ArchiveName."
    }

    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force

    if ($env:LOCALAPPDATA) {
        $LocalAppData = $env:LOCALAPPDATA
    } else {
        $LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
    }
    if ([string]::IsNullOrWhiteSpace($LocalAppData)) {
        Fail 'LOCALAPPDATA is not set.'
    }

    $InstallDir = Join-Path $LocalAppData 'AutomateSTIG'
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    foreach ($Bin in @('automatestig.exe', 'automatestig-gui.exe')) {
        $Source = Join-Path $ExtractDir $Bin
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            Fail "$Bin not found in $ArchiveName."
        }
        Copy-Item -LiteralPath $Source -Destination (Join-Path $InstallDir $Bin) -Force
    }

    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $UserPath) {
        $UserPath = ''
    }

    $NormalizedInstallDir = $InstallDir.TrimEnd('\')
    $AlreadyOnPath = $false
    foreach ($PathEntry in ($UserPath -split ';')) {
        if ($PathEntry.Trim().TrimEnd('\') -ieq $NormalizedInstallDir) {
            $AlreadyOnPath = $true
            break
        }
    }

    if (-not $AlreadyOnPath) {
        if ([string]::IsNullOrWhiteSpace($UserPath)) {
            $NewUserPath = $InstallDir
        } else {
            $NewUserPath = "$UserPath;$InstallDir"
        }
        [Environment]::SetEnvironmentVariable('Path', $NewUserPath, 'User')
        $env:Path = "$env:Path;$InstallDir"
        $PathMessage = "Added $InstallDir to your user PATH. Open a new PowerShell window if the commands are not found."
    } else {
        $PathMessage = "$InstallDir is already on your user PATH."
    }

    Write-Host "Installed AutomateSTIG $Tag to $InstallDir"
    Write-Host $PathMessage
    Write-Host 'Launch the GUI with: automatestig-gui'
    Write-Host 'CLI help: automatestig --help'
} catch {
    Write-Error "AutomateSTIG install failed: $($_.Exception.Message)"
    exit 1
} finally {
    if ($TempDir -and (Test-Path -LiteralPath $TempDir)) {
        Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
