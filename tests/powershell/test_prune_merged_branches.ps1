# Offline Windows PowerShell 5.1 integration test for the GitHub branch pruner.
# Mocks the "gh" function and verifies preview/deletion without network calls.
$ErrorActionPreference = "Stop"
$scriptFile = Join-Path $PSScriptRoot "..\..\scripts\prune_merged_github_branches.ps1"
$live1 = ("a" * 40)
$live2 = ("b" * 40)
$other = ("c" * 40)
$main = ("d" * 40)
$docsSha = ("e" * 40)
$qualitySha = ("f" * 40)
$branches = @(
    @{ name = "main"; protected = $true; commit = @{sha = $main} }
    @{ name = "refactor/merged"; protected = $false; commit = @{sha = $live1} }
    @{ name = "maintenance/merged"; protected = $false; commit = @{sha = $live2} }
    @{ name = "docs/merged"; protected = $false; commit = @{sha = $docsSha} }
    @{ name = "quality/merged"; protected = $false; commit = @{sha = $qualitySha} }
    @{ name = "fix/open"; protected = $false; commit = @{sha = $other} }
    @{ name = "release/stale"; protected = $false; commit = @{sha = $other} }
    @{ name = "refactor/protected"; protected = $true; commit = @{sha = $other} }
    @{ name = "feature/unrecognized"; protected = $false; commit = @{sha = $other} }
)
$prHead = @{repo = @{full_name = "spk-c/PenX"}}
$open = @(
    @{ head = @{ref = "fix/open"; repo = $prHead.repo; sha = $other} }
)
$closed = @(
    @{ number = 2; merged_at = "2026-10-16T11:00:00Z";
       head = @{ref = "refactor/merged"; repo = $prHead.repo; sha = $live1} }
    @{ number = 3; merged_at = "2026-10-16T12:00:00Z";
       head = @{ref = "maintenance/merged"; repo = $prHead.repo; sha = $live2} }
    @{ number = 7; merged_at = "2026-10-16T12:05:00Z";
       head = @{ref = "docs/merged"; repo = $prHead.repo; sha = $docsSha} }
    @{ number = 8; merged_at = "2026-10-16T12:06:00Z";
       head = @{ref = "quality/merged"; repo = $prHead.repo; sha = $qualitySha} }
    @{ number = 4; merged_at = "2026-10-16T13:00:00Z";
       head = @{ref = "release/stale"; repo = $prHead.repo; sha = $live1} }
    @{ number = 5; merged_at = "2026-10-16T14:00:00Z";
       head = @{ref = "refactor/protected"; repo = $prHead.repo; sha = $other} }
    @{ number = 6; merged_at = "2026-10-16T15:00:00Z";
       head = @{ref = "feature/unrecognized"; repo = $prHead.repo; sha = $other} }
)
$global:Deleted = @()
$global:Fixtures = @{
    "repos/spk-c/PenX" = '{"full_name":"spk-c/PenX","default_branch":"main"}'
    "repos/spk-c/PenX/branches?per_page=100" = (ConvertTo-Json -InputObject $branches -Depth 10 -Compress)
    "repos/spk-c/PenX/pulls?state=open&per_page=100" = (ConvertTo-Json -InputObject $open -Depth 10 -Compress)
    "repos/spk-c/PenX/pulls?state=closed&per_page=100" = (ConvertTo-Json -InputObject $closed -Depth 10 -Compress)
    "repos/spk-c/PenX/git/ref/heads/refactor/merged" = ('{"object":{"sha":"' + $live1 + '"}}')
    "repos/spk-c/PenX/git/ref/heads/maintenance/merged" = ('{"object":{"sha":"' + $live2 + '"}}')
    "repos/spk-c/PenX/git/ref/heads/docs/merged" = ('{"object":{"sha":"' + $docsSha + '"}}')
    "repos/spk-c/PenX/git/ref/heads/quality/merged" = ('{"object":{"sha":"' + $qualitySha + '"}}')
}
$global:AllowedDeletes = @(
    "repos/spk-c/PenX/git/refs/heads/refactor/merged",
    "repos/spk-c/PenX/git/refs/heads/maintenance/merged",
    "repos/spk-c/PenX/git/refs/heads/docs/merged",
    "repos/spk-c/PenX/git/refs/heads/quality/merged"
)
function global:gh {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq "auth" -and $args[1] -eq "status") { return }
    if ($args[0] -ne "api") { throw "Unexpected simulated gh command" }
    if ($args[1] -eq "-X") {
        if ($args[2] -ne "DELETE" -or $args[3] -notin $global:AllowedDeletes) {
            throw "Unsafe ref deletion attempted: $($args -join ' ')"
        }
        $global:Deleted += [string]$args[3]
        return
    }
    $endpoint = [string]$args[1]
    if (-not $global:Fixtures.ContainsKey($endpoint)) {
        throw "Unexpected API request in offline test: $endpoint"
    }
    Write-Output $global:Fixtures[$endpoint]
}
$preview = (& $scriptFile 6>&1 | Out-String)
if ($global:Deleted.Count -ne 0) { throw "Dry run deleted a branch" }
if ($preview -notmatch 'Candidates: 4') {
    throw "Expected four eligible branches in dry run, got: $preview"
}
$applied = (& $scriptFile -Apply 6>&1 | Out-String)
if ($applied -notmatch 'Candidates: 4') {
    throw "Expected four eligible branches in apply mode, got: $applied"
}
if ($global:Deleted.Count -ne 4) {
    throw "Expected exactly four fake deletion calls, got $($global:Deleted.Count): $applied"
}
foreach ($expected in $global:AllowedDeletes) {
    if ($expected -notin $global:Deleted) {
        throw "Expected verified fake DELETE call missing: $expected"
    }
}
Write-Output "PASS: PowerShell 5.1 JSON record enumeration, dry-run and safe -Apply."
