<#
.SYNOPSIS
  Collect a privacy-conscious, non-invasive PenX Windows refactor evidence record.
.DESCRIPTION
  Does NOT install anything, invoke scanners, contact a host, change databases,
  elevate privileges or attest to tests that the operator did not run. Never
  place credentials or raw target results in this file.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\collect_refactor_field_evidence.ps1 -InstallerPath ".\PenX-Setup-x64.exe"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [string]$OutputDirectory = ".\refactor-field-evidence"
)
$ErrorActionPreference = "Stop"
$installer = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
if ([IO.Path]::GetFileName($installer) -ne "PenX-Setup-x64.exe") {
    throw "Expected the official PenX-Setup-x64.exe filename. File not executed."
}
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$versionSource = Join-Path $scriptRoot "src\penx_app\version.py"
$git = Get-Command git -ErrorAction SilentlyContinue
$commit = "unavailable"
if ($git) {
    $head = & git -C $scriptRoot rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0) { $commit = $head.Trim() }
}
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
$osVersion = [Environment]::OSVersion.VersionString
$pythonVersion = "NOT RUN"
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $ver = & python --version 2>&1
    if ($LASTEXITCODE -eq 0) { $pythonVersion = "$ver".Trim() }
}
$version = "unavailable"
if (Test-Path -LiteralPath $versionSource) {
    $text = Get-Content -LiteralPath $versionSource -Raw
    if ($text -match '(?m)^VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') {
        $version = $Matches[1]
    }
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -Path $output -ItemType Directory -Force | Out-Null
$file = Join-Path $output "FIELD_ACCEPTANCE.md"
if (Test-Path -LiteralPath $file) {
    throw "Evidence file already exists: $file. Refusing to overwrite past records."
}
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lines = @(
    "# PenX Windows field acceptance - unsigned record",
    "",
    "- Timestamp (UTC): $date",
    "- Git commit: $commit",
    "- Application source version: $version",
    "- Windows OS: $osVersion",
    "- Python: $pythonVersion",
    "- Installer SHA256: $hash",
    "- Installer name: PenX-Setup-x64.exe",
    "- Status: NOT SIGNED OFF",
    "",
    "## Operator-executed field checks",
    "",
    "| Gate | Result | Evidence |",
    "| --- | --- | --- |",
    "| Pk02 portable path / writable user-data | NOT RUN | |",
    "| Pk03 restored source evidence anchors | NOT RUN | |",
    "| Pk04 process-tree cancellation / timeout | NOT RUN | |",
    "| Pk05 12-mode authorized scanner matrix | NOT RUN | |",
    "| Pk07 sanitized SQLite WAL restore | NOT RUN | |",
    "| Pk07 isolated MariaDB restore / rollback | NOT RUN | |",
    "| Pk08 live model/source timeout cases | NOT RUN | |",
    "| Pk09 interactive navigation / Esc / Ctrl+C | NOT RUN | |",
    "| Pk10 manual long HTML/PDF/JSON/SARIF review | NOT RUN | |",
    "| Pk11 first run / Npcap UAC / upgrade / rollback | NOT RUN | |",
    "| Pk12 representative hardware benchmark | NOT RUN | |",
    "",
    "## Authorization and recovery",
    "",
    "- Owned/authorized disposable scan target (redact before sharing): NOT PROVIDED",
    "- Sanitized backup fixture source and verified restore: NOT PROVIDED",
    "- Rollback/checkpoint record: NOT PROVIDED",
    "- Maintainer/date sign-off: NOT SIGNED",
    "",
    "Only change NOT RUN to PASS after doing the test and attaching evidence.",
    "Never include passwords, API keys, cookies, raw customer data or unredacted scans."
)
# Explicit per-adapter and per-scenario evidence: placeholders are NOT acceptance.
# The 12 full-scan choices are 1-9, s, c, d. Choice e is a separate opt-in.
$lines += @(
    "",
    "## Issue #81 - scanner matrix",
    "",
    "| Choice | Scanner | Result | Tool version / SHA256 | Authorized target / VM snapshot | Command / expected | Actual / stdout-stderr / export | Evidence | Reviewer/date |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    "| 1 | Nmap | NOT RUN | | | | | | |",
    "| 2 | WHOIS | NOT RUN | | | | | | |",
    "| 3 | WhatWeb | NOT RUN | | | | | | |",
    "| 4 | HTTP headers | NOT RUN | | | | | | |",
    "| 5 | DNS | NOT RUN | | | | | | |",
    "| 6 | Nikto | NOT RUN | | | | | | |",
    "| 7 | Nuclei | NOT RUN | | | | | | |",
    "| 8 | httpx | NOT RUN | | | | | | |",
    "| 9 | ffuf | NOT RUN | | | | | | |",
    "| s | Subfinder | NOT RUN | | | | | | |",
    "| c | Katana | NOT RUN | | | | | | |",
    "| d | TLS | NOT RUN | | | | | | |",
    "| e | Endpoint Mapping (separate opt-in; not full-scan preset) | NOT RUN | | | | | | |",
    "",
    "## Issue #81 - Windows controls",
    "",
    "| Control | Result | Expected / actual | VM snapshot | Sanitized evidence | Reviewer/date |",
    "| --- | --- | --- | --- | --- | --- |",
    "| consent-denial | NOT RUN | | | | |",
    "| navigation-back-esc | NOT RUN | | | | |",
    "| ctrl-c-cancel-process-tree | NOT RUN | | | | |",
    "| timeout-process-tree | NOT RUN | | | | |",
    "| missing-executable | NOT RUN | | | | |",
    "| missing-permissions | NOT RUN | | | | |",
    "| npcap-admin-uac | NOT RUN | | | | |",
    "| npcap-nonadmin | NOT RUN | | | | |",
    "",
    "## Issue #82 - recovery and upgrade matrix",
    "",
    "| Scenario | Result | Baseline / backup SHA256 | Expected / actual | Recovery / rollback | Sanitized evidence | Reviewer/date |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    "| sqlite-wal-consistent-restore | NOT RUN | | | | | |",
    "| sqlite-migration-duplicates-rollback | NOT RUN | | | | | |",
    "| mariadb-consistent-restore | NOT RUN | | | | | |",
    "| mariadb-migration-duplicates-rollback | NOT RUN | | | | | |",
    "| installer-clean-first-run | NOT RUN | | | | | |",
    "| installer-v048-upgrade | NOT RUN | | | | | |",
    "| installer-repair-abort-uninstall | NOT RUN | | | | | |",
    "| report-long-html-pdf-pagination | NOT RUN | | | | | |",
    "| report-json-sarif-html-pdf-parity | NOT RUN | | | | | |",
    "| report-interrupted-publish-recovery | NOT RUN | | | | | |",
    "",
    "Record exact build/backup hashes, expected and observed results, sanitized",
    "log paths and independent reviewer/date before changing any row to PASS.",
    "An automated template or CI fixture is never a field-test sign-off.",
    ""
)
[IO.File]::WriteAllLines($file, $lines, [System.Text.UTF8Encoding]::new($false))
Write-Host "Evidence template created: $file"
Write-Host "No installer, scanner, network target or database was executed."
