# Offline Windows PowerShell 5.1 integration test for the GitHub branch pruner.
# Mocks gh: dry-run, merged-PR proof, strict ancestor proof and safe -Apply.
$ErrorActionPreference = 'Stop'
$scriptFile = Join-Path $PSScriptRoot '..\..\scripts\prune_merged_github_branches.ps1'
$live1 = ('a' * 40)
$live2 = ('b' * 40)
$other = ('c' * 40)
$main = ('d' * 40)
$docsSha = ('e' * 40)
$qualitySha = ('f' * 40)
$ancestorSha = ('9' * 40)
$branches = @(
    @{name='main'; protected=$true; commit=@{sha=$main}}
    @{name='refactor/merged'; protected=$false; commit=@{sha=$live1}}
    @{name='maintenance/merged'; protected=$false; commit=@{sha=$live2}}
    @{name='docs/merged'; protected=$false; commit=@{sha=$docsSha}}
    @{name='quality/merged'; protected=$false; commit=@{sha=$qualitySha}}
    @{name='fix/open'; protected=$false; commit=@{sha=$other}}
    @{name='release/stale'; protected=$false; commit=@{sha=$other}}
    @{name='refactor/protected'; protected=$true; commit=@{sha=$other}}
    @{name='feature/merged'; protected=$false; commit=@{sha=$other}}
    @{name='feature/ancestor'; protected=$false; commit=@{sha=$ancestorSha}}
)
$prRepo = @{full_name='spk-c/PenX'}
$open = @(@{head=@{ref='fix/open'; repo=$prRepo; sha=$other}})
$closed = @(
    @{number=2; merged_at='2026-10-16T11:00:00Z'; head=@{ref='refactor/merged'; repo=$prRepo; sha=$live1}}
    @{number=3; merged_at='2026-10-16T12:00:00Z'; head=@{ref='maintenance/merged'; repo=$prRepo; sha=$live2}}
    @{number=7; merged_at='2026-10-16T12:05:00Z'; head=@{ref='docs/merged'; repo=$prRepo; sha=$docsSha}}
    @{number=8; merged_at='2026-10-16T12:06:00Z'; head=@{ref='quality/merged'; repo=$prRepo; sha=$qualitySha}}
    @{number=4; merged_at='2026-10-16T13:00:00Z'; head=@{ref='release/stale'; repo=$prRepo; sha=$live1}}
    @{number=5; merged_at='2026-10-16T14:00:00Z'; head=@{ref='refactor/protected'; repo=$prRepo; sha=$other}}
    @{number=6; merged_at='2026-10-16T15:00:00Z'; head=@{ref='feature/merged'; repo=$prRepo; sha=$other}}
)
$global:Fixtures = @{
    'repos/spk-c/PenX' = '{"full_name":"spk-c/PenX","default_branch":"main"}'
    'repos/spk-c/PenX/branches?per_page=100&page=1' = (ConvertTo-Json -InputObject $branches -Depth 10 -Compress)
    'repos/spk-c/PenX/pulls?state=open&per_page=100&page=1' = (ConvertTo-Json -InputObject $open -Depth 10 -Compress)
    'repos/spk-c/PenX/pulls?state=closed&per_page=100&page=1' = (ConvertTo-Json -InputObject $closed -Depth 10 -Compress)
    'repos/spk-c/PenX/compare/main...release%2Fstale' = '{"status":"diverged","ahead_by":2}'
    'repos/spk-c/PenX/compare/main...feature%2Fancestor' = '{"status":"behind","ahead_by":0}'
}
$expected = @(
    @{Name='refactor/merged'; Sha=$live1}
    @{Name='maintenance/merged'; Sha=$live2}
    @{Name='docs/merged'; Sha=$docsSha}
    @{Name='quality/merged'; Sha=$qualitySha}
    @{Name='feature/merged'; Sha=$other}
    @{Name='feature/ancestor'; Sha=$ancestorSha}
)
$global:AllowedDeletes = @()
foreach ($item in $expected) {
    $encoded = [Uri]::EscapeDataString($item.Name)
    $global:Fixtures["repos/spk-c/PenX/branches/$encoded"] =
        ('{"name":"' + $item.Name + '","protected":false,"commit":{"sha":"' + $item.Sha + '"}}')
    $global:AllowedDeletes += "repos/spk-c/PenX/git/refs/heads/$encoded"
}
$global:Deleted = @()
function global:gh {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'auth' -and $args[1] -eq 'status') { return }
    if ($args[0] -ne 'api') { throw 'Unexpected simulated gh command' }
    if ($args[1] -eq '-X') {
        if ($args[2] -ne 'DELETE' -or $args[3] -notin $global:AllowedDeletes) {
            throw "Unsafe ref deletion attempted: $($args -join ' ')"
        }
        $global:Deleted += [string]$args[3]
        return
    }
    $endpoint = [string]$args[1]
    if (-not $global:Fixtures.ContainsKey($endpoint)) {
        throw "Unexpected API request: $endpoint"
    }
    Write-Output $global:Fixtures[$endpoint]
}
$preview = (& $scriptFile 6>&1 | Out-String)
if ($global:Deleted.Count -ne 0) { throw 'Dry run deleted a branch' }
if ($preview -notmatch 'Verified candidates: 6') {
    throw "Expected six candidates in dry run, got: $preview"
}
$applied = (& $scriptFile -Apply 6>&1 | Out-String)
if ($applied -notmatch 'Verified candidates: 6') {
    throw "Expected six candidates in apply mode, got: $applied"
}
if ($global:Deleted.Count -ne 6) {
    throw "Expected exactly six fake deletion calls; got $($global:Deleted.Count): $applied"
}
foreach ($ref in $global:AllowedDeletes) {
    if ($ref -notin $global:Deleted) { throw "Missing verified fake DELETE: $ref" }
}
Write-Output 'PASS: PowerShell 5.1 mocked merged/ancestor proof, dry-run and safe -Apply.'
