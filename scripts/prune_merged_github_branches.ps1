<#
.SYNOPSIS
  Preview or delete only provably merged PenX topic branches on GitHub.
.DESCRIPTION
  Requires GitHub CLI (gh) authenticated to spk-c with repository access.
  Default is a dry run. -Apply is explicit and only deletes refs whose SHA
  still equals the head commit of a MERGED pull request in this repository.
  Never deletes main, unrecognized branch names, branches with open PRs, or
  branches with new commits since their PR was merged.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\prune_merged_github_branches.ps1
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\prune_merged_github_branches.ps1 -Apply
#>
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = "Stop"
$repo = "spk-c/PenX"

function Invoke-GhJson {
    param([Parameter(Mandatory = $true)][string]$Endpoint)
    $output = & gh api $Endpoint
    if ($LASTEXITCODE -ne 0) { throw "GitHub API failed: $Endpoint" }
    return ConvertFrom-Json -InputObject ($output -join [Environment]::NewLine)
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "Install GitHub CLI first: winget install -e --id GitHub.cli"
}
& gh auth status
if ($LASTEXITCODE -ne 0) { throw "Run gh auth login with your spk-c account" }

$metadata = Invoke-GhJson "repos/$repo"
if ($metadata.full_name -cne $repo -or $metadata.default_branch -ne "main") {
    throw "Wrong repository or default branch. No references changed."
}
$branches = @(Invoke-GhJson "repos/$repo/branches?per_page=100")
$openPRs = @(Invoke-GhJson "repos/$repo/pulls?state=open&per_page=100")
$closedPRs = @(Invoke-GhJson "repos/$repo/pulls?state=closed&per_page=100")

$candidates = @()
foreach ($branch in $branches) {
    $name = [string]$branch.name
    # Deliberately narrow scope: never delete main, dependabot, arbitrary
    # maintainer names or a newly created release tag/branch.
    if ($name -eq "main" -or $name -notmatch '^(?:fix|refactor|release)/') {
        continue
    }
    $used = @($openPRs | Where-Object {
        $_.head.ref -eq $name -and $_.head.repo -and
        $_.head.repo.full_name -eq $repo
    })
    if ($used.Count -gt 0) {
        Write-Host "[SKIP] $name : used by an open pull request"
        continue
    }
    $merged = @($closedPRs | Where-Object {
        $_.merged_at -and $_.head.repo -and
        $_.head.repo.full_name -eq $repo -and
        $_.head.ref -eq $name -and
        $_.head.sha -eq $branch.commit.sha
    })
    if ($merged.Count -eq 0) {
        Write-Host "[SKIP] $name : no matching merged PR at its current SHA"
        continue
    }
    $candidates += [PSCustomObject]@{
        Name = $name
        Sha = [string]$branch.commit.sha
        PR = $merged[0].number
    }
}

foreach ($candidate in $candidates) {
    if (-not $Apply) {
        Write-Host "[DRY RUN] $($candidate.Name) - merged PR #$($candidate.PR)"
        continue
    }
    # Revalidate that nobody pushed since the preview and that this branch
    # did not become the head of a newly opened pull request.
    $latestOpen = @(Invoke-GhJson "repos/$repo/pulls?state=open&per_page=100")
    if (@($latestOpen | Where-Object {
        $_.head.ref -eq $candidate.Name -and $_.head.repo -and
        $_.head.repo.full_name -eq $repo
    }).Count -ne 0) {
        throw "Refusing to delete a branch used by a new PR: $($candidate.Name)"
    }
    $current = Invoke-GhJson "repos/$repo/git/ref/heads/$($candidate.Name)"
    if ($current.object.sha -ne $candidate.Sha) {
        throw "Branch SHA changed. Refusing delete: $($candidate.Name)"
    }
    & gh api -X DELETE "repos/$repo/git/refs/heads/$($candidate.Name)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub refused branch deletion: $($candidate.Name)"
    }
    Write-Host "[DELETED] $($candidate.Name) (merged PR #$($candidate.PR))"
}

Write-Host "Candidates: $($candidates.Count)."
if (-not $Apply) {
    Write-Host "Dry run only; no branches deleted. Re-run with -Apply to delete verified candidates."
}
