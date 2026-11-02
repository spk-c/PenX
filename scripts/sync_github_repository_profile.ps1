<#
.SYNOPSIS
  Preview or synchronize the official PenX GitHub About description and Topics.
.DESCRIPTION
  Dry run by default. Requires 'gh auth login' with the repository's
  administration/metadata write authorization for -Apply. Does not edit
  Releases, tags, files, repository visibility, branch protection or assets.
.EXAMPLE
  .\scripts\sync_github_repository_profile.ps1
.EXAMPLE
  .\scripts\sync_github_repository_profile.ps1 -Apply
#>
[CmdletBinding()]
param([switch]$Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$profilePath = Join-Path $root 'docs\repository-profile.json'
$profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json

if ($profile.repository -cne 'spk-c/PenX') {
    throw 'Profile is only authorized for spk-c/PenX.'
}
$topics = @($profile.topics)
if ($topics.Count -gt 20 -or $topics.Count -lt 1) {
    throw 'GitHub supports 1-20 Topics per repository.'
}
if ((@($topics | Select-Object -Unique)).Count -ne $topics.Count) {
    throw 'Duplicate GitHub Topics in the profile.'
}
foreach ($topic in $topics) {
    if ($topic -cnotmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$') {
        throw "Invalid GitHub Topic: $topic"
    }
}

Write-Host "Repository: $($profile.repository)"
Write-Host "Description: $($profile.description)"
Write-Host "Homepage: $($profile.homepage)"
Write-Host "Topics ($($topics.Count)): $($topics -join ', ')"

if (-not $Apply) {
    Write-Host 'DRY RUN ONLY. Pass -Apply after authenticating GitHub CLI to update About and Topics.'
    return
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI is not installed. Install gh, then run 'gh auth login'."
}
& gh auth status --hostname github.com | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Not signed in. Run 'gh auth login' using an account that can administer spk-c/PenX."
}

$null = & gh api "repos/$($profile.repository)" --jq '.full_name'
if ($LASTEXITCODE -ne 0) { throw 'Repository access check failed.' }

# The two metadata API calls cannot be transactional; verify both afterwards.
$null = & gh api --method PATCH "repos/$($profile.repository)" `
    --raw-field "description=$($profile.description)" `
    --raw-field "homepage=$($profile.homepage)"
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to update repository description/homepage. Check administration write permission.'
}

$payload = @{ names = $topics } | ConvertTo-Json -Compress -Depth 4
$temp = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText($temp, $payload, [System.Text.UTF8Encoding]::new($false))
    $null = & gh api --method PUT "repos/$($profile.repository)/topics" --input $temp
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to update GitHub Topics. Check repository metadata permission.'
    }
}
finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

$actual = & gh api "repos/$($profile.repository)"
if ($LASTEXITCODE -ne 0) { throw 'Could not verify repository profile.' }
$verified = $actual | ConvertFrom-Json
if ($verified.description -cne $profile.description -or $verified.homepage -cne $profile.homepage) {
    throw 'Description/homepage verification failed.'
}
$actualTopics = @($verified.topics | Sort-Object)
$expectedTopics = @($topics | Sort-Object)
if (($actualTopics -join ',') -cne ($expectedTopics -join ',')) {
    throw 'Topics verification failed; GitHub may have rejected one or more values.'
}
Write-Host 'Verified GitHub About description, homepage and Topics.'
