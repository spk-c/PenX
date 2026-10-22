<#
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
#>
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
    $rulesetId = $matching[0].id
    if (-not $rulesetId) { throw "Existing ruleset does not expose an ID" }
    $remote = Invoke-GhJson "repos/$repo/rulesets/$rulesetId"
    $types = @($remote.rules | ForEach-Object { $_.type })
    $requiredTypes = @('deletion', 'non_fast_forward', 'pull_request', 'required_status_checks')
    $missingTypes = @($requiredTypes | Where-Object { $_ -notin $types })
    $checks = @($remote.rules | Where-Object { $_.type -eq 'required_status_checks' } |
        ForEach-Object { $_.parameters.required_status_checks } |
        ForEach-Object { $_.context })
    $expectedChecks = @('tests (ubuntu-latest)', 'tests (windows-latest)',
                        'Windows packaged app & installer', 'Gitleaks history and change scan')
    $missingChecks = @($expectedChecks | Where-Object { $_ -notin $checks })
    if ($remote.enforcement -ne 'active' -or $missingTypes.Count -gt 0 -or
        $missingChecks.Count -gt 0) {
        # Restore the repository's checked-in baseline, without a duplicate ruleset.
        # Owners with intentionally stricter custom settings should review first.
        & gh api -X PUT "repos/$repo/rulesets/$rulesetId" --input $rulesetPath | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restore active main protection ruleset" }
        Write-Host "[FIXED] Restored active main ruleset from reviewed template."
    }
    else { Write-Host "[OK] Existing main ruleset is active and includes required checks." }
}
# Read back from GitHub to verify effective persisted server-side configuration.
$allRulesets = @(Invoke-GhJson "repos/$repo/rulesets?per_page=100")
$activeMatch = @($allRulesets | Where-Object {
    $_.name -eq $rulesetName -and $_.enforcement -eq 'active'
})
if ($activeMatch.Count -ne 1) {
    throw "Ruleset not confirmed active on GitHub. Check repository Settings -> Rules."
}
Write-Host "[VERIFIED] GitHub returned one active PenX main ruleset."

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

# A protected, reviewed release PR must be the exact current main commit.
# CI on main runs Linux checks; real Windows + security checks run on release/* PRs.
$associated = @(Invoke-GhJson "repos/$repo/commits/$sha/pulls?per_page=100")
$releasePR = @($associated | Where-Object {
    $_.merged_at -and $_.merge_commit_sha -eq $sha -and
    $_.base.ref -eq 'main' -and $_.head.ref -like 'release/*' -and
    $_.head.repo.full_name -eq $repo
})
if ($releasePR.Count -ne 1) {
    throw "Cannot publish: main HEAD must be the squash/merge commit of a reviewed release/* PR"
}
$reviewSha = [string]$releasePR[0].head.sha
if ($reviewSha -notmatch '^[0-9a-f]{40}$') {
    throw "Cannot publish: release PR head SHA is missing or invalid"
}
$checks = Invoke-GhJson "repos/$repo/commits/$reviewSha/check-runs?per_page=100"
if ($checks.total_count -ge 100) {
    throw "Cannot publish: check results may be paginated"
}
$requiredChecks = @(
    'tests (ubuntu-latest)',
    'tests (windows-latest)',
    'Windows packaged app & installer',
    'Gitleaks history and change scan',
    'package'
)
foreach ($name in $requiredChecks) {
    $passed = @($checks.check_runs | Where-Object {
        $_.name -eq $name -and $_.status -eq 'completed' -and
        $_.conclusion -eq 'success' -and $_.head_sha -eq $reviewSha
    })
    if ($passed.Count -lt 1) {
        throw "Cannot publish: release PR required check not green: $name"
    }
}

$runs = Invoke-GhJson "repos/$repo/actions/runs?head_sha=$sha&per_page=100"
$mainPassed = @($runs.workflow_runs | Where-Object {
    $_.name -eq 'Offline tests' -and $_.event -eq 'push' -and
    $_.head_sha -eq $sha -and $_.conclusion -eq 'success'
})
if ($mainPassed.Count -lt 1) {
    throw "Cannot publish: exact main commit does not have a passing post-merge CI run"
}
$manifest = Invoke-GhJson "repos/$repo/contents/pyproject.toml?ref=main"
$pyproject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String(($manifest.content -replace "\s", ""))
)
if ($pyproject -notmatch ('(?m)^version\s*=\s*"' + [regex]::Escape($Matches[1]) + '"')) {
    throw "Cannot publish: Python package and CLI versions differ"
}

# Existing tags are immutable: never move or replace them.
$matchingTags = @(Invoke-GhJson "repos/$repo/git/matching-refs/tags/$tag")
$prior = @($matchingTags | Where-Object { $_.ref -eq "refs/tags/$tag" })
if ($prior.Count -gt 0) {
    Write-Host "[INFO] Tag $tag already exists. No tag was changed."
    Write-Host "Review https://github.com/spk-c/PenX/releases/tag/$tag"
    exit 0
}
# GitHub user-authenticated tag creation triggers the checked-in tagged-release workflow.
& gh api -X POST "repos/$repo/git/refs" -f "ref=refs/tags/$tag" -f "sha=$sha" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not create release tag $tag" }
Write-Host "[OK] Created immutable tag $tag at $sha; Windows Release will verify assets before publication."
Write-Host "Follow: https://github.com/spk-c/PenX/actions/workflows/release.yml"
