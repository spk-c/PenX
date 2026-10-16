# Build and smoke-test both PenX Windows editions on a trusted GitLab
# Windows hosted runner. Tag pipelines also upload verified release assets.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Assert-ExitCode([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" }
}

$pythonCandidates = @(
    'C:\Python313\python.exe',
    'C:\Program Files\Python313\python.exe',
    'C:\hostedtoolcache\windows\Python\3.13\x64\python.exe'
)
$python = $pythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $python) {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        throw 'Python 3.13 not found and Chocolatey is unavailable.'
    }
    choco install python313 --yes --no-progress --limit-output
    Assert-ExitCode 'Python 3.13 installation'
    $python = $pythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $python) { throw 'Python 3.13 executable not found.' }
& $python --version
Assert-ExitCode 'Python interpreter'

$env:PYTHONPATH = 'src'
& $python -m pip install --disable-pip-version-check --prefer-binary --require-hashes -r requirements.lock.txt
Assert-ExitCode 'Pinned dependencies'
& $python -m pip install --disable-pip-version-check --prefer-binary -r requirements-build.txt
Assert-ExitCode 'Build dependencies'
& $python -m pip check
Assert-ExitCode 'pip check'
& $python offline_tests.py
Assert-ExitCode 'Offline regression tests'

$version = (& $python -c 'from penx_app.version import VERSION; print(VERSION)').Trim()
Assert-ExitCode 'Version lookup'
if ($env:CI_COMMIT_TAG -and $env:CI_COMMIT_TAG -ne "v$version") {
    throw "Release tag $env:CI_COMMIT_TAG differs from app version v$version"
}

& $python scripts/build_windows.py
Assert-ExitCode 'PyInstaller build'
& '.\dist\PenX\PenX.exe' --version
Assert-ExitCode 'Windows executable'
& '.\dist\PenX\PenX.exe' --setup-status
Assert-ExitCode 'Windows scanner setup status'

$compiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $compiler)) {
    choco install innosetup --yes --no-progress --limit-output
    Assert-ExitCode 'Inno Setup installation'
}
if (-not (Test-Path $compiler)) { throw 'Inno Setup compiler missing' }
& $compiler "/DMyAppVersion=$version" 'installer/penx.iss'
Assert-ExitCode 'Installer compilation'

New-Item -ItemType Directory -Path dist -Force | Out-Null
Compress-Archive -LiteralPath 'dist\PenX' -DestinationPath 'dist\PenX-Windows-x64.zip' -CompressionLevel Optimal -Force
foreach ($file in @('PenX-Setup-x64.exe', 'PenX-Windows-x64.zip')) {
    if (-not (Test-Path (Join-Path dist $file))) { throw "Missing expected artifact $file" }
}
$files = @('PenX-Setup-x64.exe', 'PenX-Windows-x64.zip')
$lines = foreach ($file in $files) {
    $sha = (Get-FileHash (Join-Path dist $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$sha  $file"
}
$lines | Set-Content -Encoding ascii 'dist\SHA256SUMS.txt'
Get-Content 'dist\SHA256SUMS.txt'

# No release is published before the tag-specific Windows build succeeds.
if ($env:CI_COMMIT_TAG) {
    if (-not $env:CI_JOB_TOKEN -or -not $env:CI_API_V4_URL -or -not $env:CI_PROJECT_ID) {
        throw 'Missing GitLab CI upload credentials'
    }
    foreach ($file in @('PenX-Setup-x64.exe', 'PenX-Windows-x64.zip', 'SHA256SUMS.txt')) {
        $uri = "$env:CI_API_V4_URL/projects/$env:CI_PROJECT_ID/packages/generic/penx/$env:CI_COMMIT_TAG/$file"
        Invoke-WebRequest -Uri $uri -Method Put -Headers @{'JOB-TOKEN' = $env:CI_JOB_TOKEN} -InFile (Join-Path dist $file) -ContentType 'application/octet-stream' -UseBasicParsing | Out-Null
        Write-Host "Uploaded $file to GitLab Package Registry"
    }
}
