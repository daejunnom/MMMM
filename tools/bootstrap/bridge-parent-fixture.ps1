# The leader exits while a Job-owned native child is still alive. A short child
# must drain naturally; a long child must be reported and killed after grace.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('NaturalChild','LingeringChild')][string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $IsWindows) { throw 'This fixture child requires Windows.' }
$commandApplication=Get-Command cmd -CommandType Application -ErrorAction Stop | Select-Object -First 1
if ($null -eq $commandApplication -or $commandApplication.Source -isnot [string] -or -not [System.IO.Path]::IsPathFullyQualified($commandApplication.Source)) { throw 'Fixture cmd must use one literal absolute executable path.' }
$command=[System.IO.Path]::GetFullPath($commandApplication.Source)
if (([System.IO.File]::GetAttributes($command) -band ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint)) -ne 0) { throw 'Fixture cmd executable must be a regular literal file.' }
$start=[System.Diagnostics.ProcessStartInfo]::new()
$start.FileName=$command
$start.UseShellExecute=$false
$start.CreateNoWindow=$true
$start.ArgumentList.Add('/d')
$start.ArgumentList.Add('/c')
# Fixed loopback commands avoid tool downloads and external network dependencies.
# Two pings take about one second; thirty-one take about thirty seconds.
if ($Case -eq 'NaturalChild') { $start.ArgumentList.Add('ping -n 2 127.0.0.1 >NUL') }
else { $start.ArgumentList.Add('ping -n 31 127.0.0.1 >NUL') }
$ownedChild=[System.Diagnostics.Process]::Start($start)
if ($null -eq $ownedChild) { throw 'Fixture native child did not start.' }
[Console]::Out.WriteLine('bridge native child started; pid=' + $ownedChild.Id)
$ownedChild.Dispose()
exit 0
