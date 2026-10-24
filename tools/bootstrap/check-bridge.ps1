# The first real bootstrap exposed a PowerShell $null -> String.Empty callback
# conversion that source parsing could not verify. This fixture crosses that
# same native job, pipe, delegate, five-second observation and drain boundary.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [ValidateSet('NullObserver','NaturalChild','LingeringChild','OwnedBuildTail')][string]$Case='NullObserver'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.2' -or -not $IsWindows) {
    throw 'Bridge fixture requires Windows and PowerShell Core 7.2 or later.'
}
if (-not [System.IO.Path]::IsPathFullyQualified($EvidenceRoot)) { throw 'Fixture evidence root must be absolute.' }
$requested = [System.IO.Path]::GetFullPath($EvidenceRoot)
if ($requested.StartsWith('\\')) { throw 'Fixture evidence must use a local root.' }
foreach ($part in $requested.Split([char]'\',[System.StringSplitOptions]::RemoveEmptyEntries)) {
    $name=$part.ToLowerInvariant()
    if ($name -eq '.env' -or $name.StartsWith('.env.') -or $name -eq '.ssh' -or
        $name -in @('id_rsa','id_ed25519') -or $name.Contains('credential') -or
        $name.Contains('service-account') -or $name.Contains('service_account') -or
        $name.Contains('api-key') -or $name.Contains('api_key')) { throw 'Secret-named fixture roots are rejected.' }
}
if (-not [System.IO.Directory]::Exists($requested)) { throw 'The task owner must provide an existing empty fixture evidence directory.' }
foreach ($ancestor in [System.IO.DirectoryInfo]::new($requested), [System.IO.DirectoryInfo]::new($requested).Parent) {
    $directory=$ancestor
    while ($null -ne $directory) {
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture evidence ancestry contains a reparse point.' }
        $directory=$directory.Parent
    }
}
if (@([System.IO.Directory]::EnumerateFileSystemEntries($requested)).Count -ne 0) { throw 'Fixture evidence root must be empty.' }
Add-Type -Path ([System.IO.Path]::Combine($PSScriptRoot,'WindowsBootstrap.cs'))
$evidence=[Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($requested)
$utf8=[System.Text.UTF8Encoding]::new($false,$true)
function Write-FixtureRecord([string]$Name,$Value) {
    $bytes=$utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 6 -Compress))
    if ($bytes.Length -gt 8192) { throw 'Fixture record exceeds 8 KiB.' }
    $file=[System.IO.FileStream]::new([System.IO.Path]::Combine($evidence,$Name),[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
$fixtureToken=[System.Guid]::NewGuid().ToString('N')
Write-FixtureRecord 'bridge-owner.json' ([ordered]@{schema='mmmm-bootstrap-bridge-owner/1';token=$fixtureToken;pid=$PID;purpose=('bootstrap-bridge-' + $Case.ToLowerInvariant())})
$script:mmmmBridgeObservationCount=0
$observer=[System.Func[string]]{ $script:mmmmBridgeObservationCount++; return $null }
$pwshApplication=Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1
if ($null -eq $pwshApplication -or $pwshApplication.Source -isnot [string] -or -not [System.IO.Path]::IsPathFullyQualified($pwshApplication.Source)) { throw 'Fixture PowerShell must use one literal absolute executable path.' }
$pwsh=[System.IO.Path]::GetFullPath($pwshApplication.Source)
if (([System.IO.File]::GetAttributes($pwsh) -band ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint)) -ne 0) { throw 'Fixture PowerShell executable must be a regular literal file.' }
if ($Case -eq 'NullObserver') {
    $child=[string[]]@('-NoProfile','-NonInteractive','-Command',"Start-Sleep -Milliseconds 6200; [Console]::Out.WriteLine('bridge fixture completed'); exit 0")
} else {
    $childCase=if ($Case -eq 'OwnedBuildTail') { 'LingeringChild' } else { $Case }
    $child=[string[]]@('-NoProfile','-NonInteractive','-File',[System.IO.Path]::Combine($PSScriptRoot,'bridge-parent-fixture.ps1'),'-Case',$childCase)
}
$result=[Mmmm.Bootstrap.WindowsBoundary]::Run($pwsh,$child,$evidence,
    [System.IO.Path]::Combine($evidence,'bridge.stdout.log'),[System.IO.Path]::Combine($evidence,'bridge.stderr.log'),20,$observer,($Case -eq 'OwnedBuildTail'))
$passed=$result.CommandExit -eq 0 -and $result.Drained
if ($Case -eq 'NullObserver') {
    $passed=$passed -and $result.SupervisorErrors.Length -eq 0 -and $script:mmmmBridgeObservationCount -ge 1 -and -not $result.OwnedTailTerminated
} elseif ($Case -eq 'NaturalChild') {
    $passed=$passed -and $result.SupervisorErrors.Length -eq 0 -and $result.MaximumPostLeaderProcesses -ge 1 -and -not $result.OwnedTailTerminated
} elseif ($Case -eq 'OwnedBuildTail') {
    $passed=$passed -and $result.SupervisorErrors.Length -eq 0 -and $result.MaximumPostLeaderProcesses -ge 1 -and $result.OwnedTailTerminated
} else {
    $passed=$passed -and -not $result.OwnedTailTerminated -and $result.MaximumPostLeaderProcesses -ge 1 -and $result.SupervisorErrors.Length -eq 1 -and
        $result.SupervisorErrors[0].StartsWith('command exited with live owned children after 2000 ms natural drain grace; active=')
}
$receipt=[ordered]@{schema='mmmm-bootstrap-bridge-result/1';token=$fixtureToken;case=$Case;command_exit=$result.CommandExit;drained=$result.Drained;supervisor_errors=@($result.SupervisorErrors);owned_tail_terminated=$result.OwnedTailTerminated;elapsed_ms=$result.ElapsedMilliseconds;budget_callbacks=$script:mmmmBridgeObservationCount;max_post_leader_processes=$result.MaximumPostLeaderProcesses;passed=$passed}
Write-FixtureRecord 'bridge-result.json' $receipt
$receipt | ConvertTo-Json -Depth 6 -Compress
if (-not $passed) { exit 1 }
