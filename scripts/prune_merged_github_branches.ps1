<#
.SYNOPSIS
  Preview or prune verified merged/ancestor PenX topic branches.
.DESCRIPTION
  Requires an authenticated GitHub CLI with spk-c/PenX administration rights.
  The default is a read-only dry run. -Apply opts into deletion.
  Eligible branches are either:
    (1) exact head SHA of a merged pull request in spk-c/PenX; or
    (2) strict ancestors of main (zero commits ahead).
  Refuses open pull requests, protected branches, changed ref SHAs, unknown
  prefixes, API pagination errors and incomplete comparison results.
  Branches/tags in releases and main are never targeted.
  This cannot make deletion atomic: GitHub's DELETE ref API has no SHA lease.
.EXAMPLE
  pwsh -NoProfile -File .\scripts\prune_merged_github_branches.ps1
.EXAMPLE
  pwsh -NoProfile -File .\scripts\prune_merged_github_branches.ps1 -Apply
#>
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'
$repo = 'spk-c/PenX'
$eligiblePrefix = '^(?:chore|docs|feat|feature|fix|maintenance|quality|refactor|release)/'
$main = 'main'

function Invoke-GhJson {
    param([Parameter(Mandatory=$true)][string]$Endpoint)
    $raw = & gh api $Endpoint
    if ($LASTEXITCODE -ne 0) { throw "GitHub API failed: $Endpoint" }
    $joined = $raw -join [Environment]::NewLine
    if (-not $joined.Trim()) { throw "Empty API result: $Endpoint" }
    return ConvertFrom-Json -InputObject $joined
}

function Get-GhPages {
    param([Parameter(Mandatory=$true)][string]$Endpoint)
    $items = [Collections.Generic.List[object]]::new()
    for ($page = 1; $page -le 50; $page++) {
        $separator = if ($Endpoint.Contains('?')) { '&' } else { '?' }
        $records = @(Invoke-GhJson "$Endpoint${separator}per_page=100&page=$page")
        if ($records.Count -eq 1 -and $records[0] -is [System.Array]) {
            $records = @($records[0])
        }
        foreach ($item in $records) {
            if ($null -eq $item -or $item -is [System.Array]) {
                throw "Unexpected paged response for $Endpoint"
            }
            $items.Add($item)
        }
        if ($records.Count -lt 100) { return $items.ToArray() }
    }
    throw "Pagination limit reached for $Endpoint; refusing cleanup"
}

function Get-Comparison {
    param([string]$Ref)
    # Compare main (base) to candidate (head): strict ancestors have status=behind and ahead_by=0.
    # URL-encode each branch ref; slash-containing topic names are supported.
    $encoded = [Uri]::EscapeDataString($Ref)
    return Invoke-GhJson "repos/$repo/compare/$main...$encoded"
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'Install GitHub CLI first: winget install -e --id GitHub.cli'
}
& gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login with repo admin access' }
$metadata = Invoke-GhJson "repos/$repo"
if ($metadata.full_name -cne $repo -or $metadata.default_branch -ne $main) {
    throw 'Unexpected repository/default branch; no refs changed'
}
$branches = @(Get-GhPages "repos/$repo/branches")
$openPRs = @(Get-GhPages "repos/$repo/pulls?state=open")
$closedPRs = @(Get-GhPages "repos/$repo/pulls?state=closed")

$candidates = @()
foreach ($b in $branches) {
    $name = [string]$b.name
    if ($name -eq $main -or $b.protected -or $name -cnotmatch $eligiblePrefix) {
        continue
    }
    if ($name -notmatch '^[a-zA-Z0-9._/-]+$') {
        Write-Host "[SKIP] Unsupported branch characters: $name"
        continue
    }
    $open = @($openPRs | Where-Object {
        $_.head.ref -ceq $name -and $_.head.repo.full_name -ceq $repo
    })
    if ($open.Count -gt 0) {
        Write-Host "[SKIP] $name has an open PR"
        continue
    }

    $merged = @($closedPRs | Where-Object {
        $_.merged_at -and $_.head.ref -ceq $name -and
        $_.head.repo.full_name -ceq $repo -and
        $_.head.sha -ceq $b.commit.sha
    })
    $reason = $null
    if ($merged.Count -gt 0) {
        $reason = "merged PR #$($merged[0].number) at exact head SHA"
    }
    else {
        $comparison = Get-Comparison $name
        if ($comparison.status -in @('behind','identical') -and
            $null -ne $comparison.ahead_by -and
            [int]$comparison.ahead_by -eq 0) {
            $reason = 'ancestor of main (zero commits ahead)'
        }
    }
    if (-not $reason) {
        Write-Host "[KEEP] $name has unverified/unmerged commits"
        continue
    }
    $candidates += [PSCustomObject]@{
        Name = $name
        Sha = [string]$b.commit.sha
        Reason = $reason
        HasMergedPr = ($merged.Count -gt 0)
    }
}

foreach ($candidate in $candidates) {
    if (-not $Apply) {
        Write-Host "[DRY RUN] $($candidate.Name) - $($candidate.Reason)"
        continue
    }
    # Revalidate open PRs, SHA, protection and merge/ancestor evidence.
    $currentOpen = @(Get-GhPages "repos/$repo/pulls?state=open")
    if (@($currentOpen | Where-Object {
        $_.head.ref -ceq $candidate.Name -and $_.head.repo.full_name -ceq $repo
    }).Count -gt 0) {
        throw "New open PR for $($candidate.Name); stopping"
    }
    $encoded = [Uri]::EscapeDataString($candidate.Name)
    $current = Invoke-GhJson "repos/$repo/branches/$encoded"
    if ($current.commit.sha -cne $candidate.Sha -or $current.protected) {
        throw "Branch moved or became protected: $($candidate.Name); stopping"
    }
    if ($candidate.HasMergedPr) {
        $nowClosed = @(Get-GhPages "repos/$repo/pulls?state=closed")
        $exact = @($nowClosed | Where-Object {
            $_.merged_at -and $_.head.ref -ceq $candidate.Name -and
            $_.head.repo.full_name -ceq $repo -and
            $_.head.sha -ceq $candidate.Sha
        })
        if ($exact.Count -eq 0) { throw "Merge proof disappeared: $($candidate.Name)" }
    }
    else {
        $comparison = Get-Comparison $candidate.Name
        if ($comparison.status -notin @('behind','identical') -or
            $null -eq $comparison.ahead_by -or
            [int]$comparison.ahead_by -ne 0) {
            throw "Ancestor proof no longer valid: $($candidate.Name)"
        }
    }
    & gh api -X DELETE "repos/$repo/git/refs/heads/$encoded" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Deletion failed: $($candidate.Name)" }
    Write-Host "[DELETED] $($candidate.Name) - $($candidate.Reason)"
}
Write-Host "Verified candidates: $($candidates.Count) / $($branches.Count - 1) topic branches."
if (-not $Apply) { Write-Host 'Dry run only; no branches deleted. Use -Apply to prune verified candidates.' }
