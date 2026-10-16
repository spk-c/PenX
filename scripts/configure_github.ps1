<##>
.SYNOPSIS
  Configure the spk-c/PenX GitHub repository and optionally start its first release.
.DESCRIPTION
  Requires GitHub CLI authenticated as a repository administrator. This script
  never embeds credentials or uploads release binaries. The release is built by
  the existing GitHub Actions tag workflow after it verifies Windows artifacts.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/configure_github.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/configure_github.ps1 -PublishRelease
##>
[CmdletBinding()]
param([switch]$PublishRelease)

$ErrorActionPreference = "Stop"
$repo = "spk-c/PenX"
$description = "Open-source Windows-first security reconnaissance with 12 scanner options, local AI, and HTML/PDF/SARIF reports."
$homepage = "https://github.com/spk-c/PenX/releases"
$rulesetName = "PenX protect main (PR + CI)"
$root = Split-Path -Parent $PSScriptRoot
$rulesetPath = Join-Path $root ".github/rulesets/protect-main.json"

function Invoke-GhJson {
    param([Parameter(Mandatory = $true)][string]$Endpoint)
    $output = & gh api $Endpoint
    if ($LASTEXITCODE -ne 0) { throw "GitHub API request failed: $Endpoint" }
    $raw = $output -join [Environment]::NewLine
    if (-not $raw.Trim()) { return $null }
    return ConvertFrom-Json -InputObject $raw
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI missing. Install: winget install -e --id GitHub.cli"
}
& gh auth status
if ($LASTEXITCODE -ne 0) {
    throw "Log in to the spk-c account using: gh auth login"
}

$project = Invoke-GhJson "repos/$repo"
if ($project.full_name -ne $repo -or $project.default_branch -ne "main") {
    throw "Wrong GitHub repository or default branch. No changes made."
}
Write-Host "[1/3] Updating GitHub repository About..."
& gh repo edit $repo --description $description --homepage $homepage
if ($LASTEXITCODE -ne 0) { throw "Cannot edit repository About settings" }

$topics = @{
    names = @("cybersecurity", "security-tools", "penetration-testing",
              "recon", "vulnerability-assessment", "network-scanner",
              "windows", "python", "local-ai", "nmap", "nuclei",
              "ffuf", "subfinder", "katana", "httpx")
} | ConvertTo-Json -Depth 4
$tempFile = Join-Path ([IO.Path]::GetTempPath()) ("penx-topics-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    [IO.File]::WriteAllText($tempFile, $topics, [Text.UTF8Encoding]::new($false))
    & gh api -X PUT "repos/$repo/topics" --input $tempFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot save GitHub topics" }
}
finally { Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue }

Write-Host "[2/3] Ensuring GitHub main branch ruleset..."
if (-not (Test-Path -LiteralPath $rulesetPath)) { throw "Ruleset JSON missing" }
$parsed = Get-Content -LiteralPath $rulesetPath -Raw | ConvertFrom-Json
if ($parsed.name -ne $rulesetName -or $parsed.enforcement -ne "active") {
    throw "Unexpected main ruleset template"
}
$existingRulesets = @(Invoke-GhJson "repos/$repo/rulesets?per_page=100")
$matching = @($existingRulesets | Where-Object { $_.name -eq $rulesetName })
if ($matching.Count -gt 1) { throw "Duplicate PenX rulesets; review settings manually" }
if ($matching.Count -eq 0) {
    & gh api -X POST "repos/$repo/rulesets" --input $rulesetPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot create main ruleset (requires admin permission)"
    }
    Write-Host "[OK] Ruleset created; direct pushes to main require a PR."
}
else {
    Write-Host "[OK] Ruleset already exists: review its enforcement in GitHub settings."
}

Write-Host "[3/3] Repository settings checked."
if (-not $PublishRelease) {
    Write-Host "Release not started. After CI passes, rerun with -PublishRelease."
    exit 0
}

$branch = Invoke-GhJson "repos/$repo/git/ref/heads/main"
$sha = $branch.object.sha
$versionFile = Invoke-GhJson "repos/$repo/contents/src/penx_app/version.py?ref=main"
$bytes = [Convert]::FromBase64String(($versionFile.content -replace "\s", ""))
$source = [Text.Encoding]::UTF8.GetString($bytes)
if ($source -notmatch '(?m)^VERSION\s*=\s*"(\d+\.\d+\.\d+)"') {
    throw "Could not determine the current application version"
}
$tag = "v" + $Matches[1]
Write-Host "Preparing $tag from main commit $sha"

$runs = Invoke-GhJson "repos/$repo/actions/runs?head_sha=$sha&per_page=100"
foreach ($name in @("Offline tests", "Python compatibility contracts", "Security audit")) {
    $passed = @($runs.workflow_runs | Where-Object {
        $_.name -eq $name -and $_.conclusion -eq "success"
    })
    if ($passed.Count -lt 1) { throw "Cannot publish: $name has not passed for $sha" }
}

$offline = @($runs.workflow_runs | Where-Object {
    $_.name -eq "Offline tests" -and $_.conclusion -eq "success"
} | Select-Object -First 1)
$jobs = Invoke-GhJson "repos/$repo/actions/runs/$($offline[0].id)/jobs?per_page=100"
foreach ($name in @("tests (ubuntu-latest)", "tests (windows-latest)",
                    "Windows packaged app & installer")) {
    if (@($jobs.jobs | Where-Object {
        $_.name -eq $name -and $_.conclusion -eq "success"
    }).Count -ne 1) {
        throw "Cannot publish: required Windows/Linux packaging check not green: $name"
    }
}

$matchingTags = @(Invoke-GhJson "repos/$repo/git/matching-refs/tags/$tag")
$prior = @($matchingTags | Where-Object { $_.ref -eq "refs/tags/$tag" })
if ($prior.Count -gt 0) {
    Write-Host "[INFO] Tag $tag already exists. No tag was modified."
    Write-Host "Check https://github.com/spk-c/PenX/actions/workflows/release.yml"
    exit 0
}
& gh api -X POST "repos/$repo/git/refs" -f "ref=refs/tags/$tag" -f "sha=$sha" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not create release tag $tag" }
Write-Host "[OK] Created $tag. The Windows Release workflow will build and publish binaries after verification."
Write-Host "Follow: https://github.com/spk-c/PenX/actions/workflows/release.yml"
