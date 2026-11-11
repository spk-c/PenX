# Read-only Authenticode gate for a separately trusted release candidate.
# Does not sign, upload, install, execute, or publish the selected artifact.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [switch]$RequireTimestamp
)

$ErrorActionPreference = 'Stop'

function Get-LocalSha256([string]$Path) {
    # Avoid optional PowerShell module auto-loading differences on Windows.
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open(
            $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        try {
            return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
        }
        finally { $stream.Dispose() }
    }
    finally { $hash.Dispose() }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
        throw 'Authenticode acceptance requires Windows.'
    }
    $resolved = (Resolve-Path -LiteralPath $ArtifactPath -ErrorAction Stop).ProviderPath
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if ($file.PSIsContainer -or
        [IO.Path]::GetExtension($resolved) -ine '.exe' -or
        (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Only regular, non-reparse-point Windows .exe files are accepted.'
    }

    $first = (Get-LocalSha256 -Path $resolved)
    if ($first -ine $ExpectedSha256) {
        throw 'SHA-256 differs from the independently trusted artifact digest.'
    }
    # If this host cannot load its security module, validation must fail closed.
    # Do not grant trust based on an SHA-256 match alone.
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved -ErrorAction Stop
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw 'Authenticode signature is missing, invalid or untrusted on this host.'
    }
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ine $ExpectedSignerThumbprint) {
        throw 'Signer certificate differs from the independently approved thumbprint.'
    }
    if ($RequireTimestamp -and $null -eq $signature.TimeStamperCertificate) {
        throw 'Required Authenticode timestamp certificate is missing.'
    }
    $second = (Get-LocalSha256 -Path $resolved)
    if ($first -ine $second) {
        throw 'Artifact bytes changed during verification.'
    }

    [ordered]@{
        scheme = 'Authenticode'
        signature_status = 'Valid-on-current-Windows-host'
        sha256 = $second.ToLowerInvariant()
        signer_thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        timestamp_certificate_present = ($null -ne $signature.TimeStamperCertificate)
        release_published = $false
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    Write-Error ('Signature verification refused: ' + $_.Exception.Message)
    exit 1
}
