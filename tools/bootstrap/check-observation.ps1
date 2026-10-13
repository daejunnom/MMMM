# Run only in a new, explicitly owned external evidence directory. The real CI
# failure occurred after Cargo removed an enumerated object file. This fixture
# removes its own leaf at that exact metadata boundary and wraps the real absence
# twice, without starting Cargo or executing bootstrap's main script.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidenceRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.2' -or -not $IsWindows) {
    throw 'Observation fixture requires Windows and PowerShell Core 7.2 or later.'
}
$bootstrapSource = [System.IO.Path]::Combine($PSScriptRoot,'bootstrap.ps1')
$tokens = $null; $parseErrors = $null
$bootstrapAst = [System.Management.Automation.Language.Parser]::ParseFile($bootstrapSource,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Bootstrap source did not parse.' }
$requiredFunctions = @('Assert-SafeName','Assert-SafeFile','Assert-Directory','Assert-Within',
    'Test-TransientMissingException','Assert-TransientMissingBoundary','Measure-Tree')
$functionSources = @{}
foreach ($name in $requiredFunctions) {
    $functions = @($bootstrapAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$false))
    if ($functions.Count -ne 1) { throw 'Fixture requires one exact bootstrap function per name.' }
    $functionSources[$name] = $functions[0].Extent.Text
    . ([scriptblock]::Create($functionSources[$name]))
}
$evidence = Assert-Directory $EvidenceRoot $false
if (@([System.IO.Directory]::EnumerateFileSystemEntries($evidence)).Count -ne 0) { throw 'Fixture evidence directory must be empty.' }
Add-Type -Path ([System.IO.Path]::Combine($PSScriptRoot,'WindowsBootstrap.cs'))
$evidence = [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($evidence)
Assert-Directory $evidence $false | Out-Null
$fixtureToken = [System.Guid]::NewGuid().ToString('N')
$utf8 = [System.Text.UTF8Encoding]::new($false,$true)
function Write-FixtureRecord([string]$Name,$Value) {
    Assert-SafeFile $Name
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 6 -Compress))
    if ($bytes.Length -gt 8192) { throw 'Observation fixture record exceeds 8 KiB.' }
    $stream = [System.IO.FileStream]::new([System.IO.Path]::Combine($evidence,$Name),[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
Write-FixtureRecord 'observation-owner.json' ([ordered]@{schema='mmmm-bootstrap-observation-owner/1';token=$fixtureToken;pid=$PID;purpose='bootstrap-observation-regression'})
$cases = [System.Collections.Generic.List[string]]::new()
function Check-Classification([string]$Name,[System.Exception]$Cause,[bool]$Expected) {
    if ((Test-TransientMissingException $Cause) -ne $Expected) { throw ('Observation classification failed: ' + $Name) }
    $cases.Add($Name)
}
$missing = [System.IO.FileNotFoundException]::new('fixture absence')
Check-Classification 'actual-file-absence' $missing $true
Check-Classification 'nested-directory-absence' ([System.Management.Automation.MethodInvocationException]::new('fixture method',
    [System.Reflection.TargetInvocationException]::new([System.IO.DirectoryNotFoundException]::new('fixture directory')))) $true
Check-Classification 'access-denied' ([System.Management.Automation.MethodInvocationException]::new('fixture method',
    [System.UnauthorizedAccessException]::new('fixture denied'))) $false
Check-Classification 'generic-io-with-absence-message' ([System.IO.IOException]::new('Could not find file')) $false
Check-Classification 'foreign-wrapper' ([System.InvalidOperationException]::new('fixture foreign',$missing)) $false
Check-Classification 'error-record-placeholder' ([System.Management.Automation.ParentContainsErrorRecordException]::new($missing)) $false
Check-Classification 'native-code-without-absence-type' ([System.ComponentModel.Win32Exception]::new(2)) $false
Check-Classification 'null-cause' $null $false
$bounded = $missing
for ($index = 0; $index -lt 8; $index++) { $bounded = [System.Reflection.TargetInvocationException]::new($bounded) }
Check-Classification 'eight-wrapper-boundary' $bounded $true
Check-Classification 'excess-wrapper-depth' ([System.Reflection.TargetInvocationException]::new($bounded)) $false

# The trusted fixture rewrites this one metadata expression in its in-memory
# function only. Production receives no test hook or caller-controlled callback.
$metadata = 'try { $attributes = [System.IO.File]::GetAttributes($entry) }'
$treeSource = [string]$functionSources['Measure-Tree']
if ($treeSource.Split([string[]]@($metadata),[System.StringSplitOptions]::None).Count -ne 2) {
    throw 'Fixture metadata interposition requires one exact source expression.'
}
. ([scriptblock]::Create($treeSource.Replace($metadata,
    'try { Invoke-FixtureMetadataBoundary $entry $depth $TransientRoots.Count ($null -ne $transientRoot); $attributes = [System.IO.File]::GetAttributes($entry) }')))
$owned = Assert-Directory ([System.IO.Path]::Combine($evidence,'fixture')) $true
$cache = Assert-Directory ([System.IO.Path]::Combine($owned,'cache','cargo-target')) $true
$deps = Assert-Directory ([System.IO.Path]::Combine($cache,'debug','deps')) $true
$leaf = [System.IO.Path]::Combine($deps,'generic_array-fixture.generic_array-cgu.0.rcgu.o')
$script:observationIdentities = @{ $cache = [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($cache).ToLowerInvariant() }
$script:fixtureMetadataPath = $null
$script:fixtureMetadataCalls = 0
$script:fixtureMetadataCase = $null
$script:fixtureMetadataDepth = -1
$script:fixtureMetadataRootCount = -1
$script:fixtureMetadataRootSelected = $false
function Get-FixtureExceptionTypes([System.Exception]$Cause) {
    $types = [System.Collections.Generic.List[string]]::new()
    for ($depth = 0; $depth -le 8 -and $null -ne $Cause; $depth++) {
        $types.Add($Cause.GetType().FullName)
        $Cause = $Cause.InnerException
    }
    if ($null -ne $Cause) { $types.Add('<depth-limit>') }
    return ,$types.ToArray()
}
function Invoke-FixtureMetadataBoundary([string]$Entry,[int]$Depth,[int]$RootCount,[bool]$RootSelected) {
    if ($Entry -cne $script:fixtureMetadataPath) { return }
    $script:fixtureMetadataCalls++
    if ($script:fixtureMetadataCalls -ne 1) { throw 'Fixture metadata fault must execute exactly once.' }
    $script:fixtureMetadataDepth = $Depth
    $script:fixtureMetadataRootCount = $RootCount
    $script:fixtureMetadataRootSelected = $RootSelected
    Assert-Within $Entry $owned
    Assert-SafeFile $Entry
    # This is one newly authored fixture leaf, never an existing cache or lease.
    [System.IO.File]::Delete($Entry)
    try { [System.IO.File]::GetAttributes($Entry) | Out-Null; throw 'Fixture leaf did not disappear.' }
    catch {
        $nativeCause = $_.Exception
        if (-not (Test-TransientMissingException $nativeCause)) { throw }
        $wrappedCause = [System.Management.Automation.MethodInvocationException]::new('fixture metadata invocation',
            [System.Reflection.TargetInvocationException]::new($nativeCause))
        # RuntimeException-derived wrappers expose an IContainsErrorRecord
        # placeholder in their own ErrorRecord. Give throw a new ErrorRecord
        # retaining the real wrapper; never permit that placeholder as absence.
        $wrappedRecord = [System.Management.Automation.ErrorRecord]::new($wrappedCause,
            'MMMMBootstrapFixtureMetadata',[System.Management.Automation.ErrorCategory]::ObjectNotFound,$null)
        if (-not [object]::ReferenceEquals($wrappedRecord.Exception,$wrappedCause)) { throw 'Fixture error record lost its actual exception.' }
        Write-FixtureRecord ($script:fixtureMetadataCase + '.metadata.json') ([ordered]@{
            native_types = Get-FixtureExceptionTypes $nativeCause
            thrown_types = Get-FixtureExceptionTypes $wrappedRecord.Exception
            entry_depth = $Depth
            active_root_count = $RootCount
            transient_root_selected = $RootSelected
            native_absence_classified = Test-TransientMissingException $nativeCause
            thrown_absence_classified = Test-TransientMissingException $wrappedRecord.Exception
        })
        throw $wrappedRecord
    }
}
function Check-MetadataRace([string]$Name,[string]$FaultPath,[string[]]$ActiveRoots,[bool]$Allowed,[int]$ExpectedDepth) {
    Assert-Within $FaultPath $owned
    [System.IO.File]::WriteAllBytes($FaultPath,[byte[]]@(1,2,3))
    $script:fixtureMetadataPath = $FaultPath; $script:fixtureMetadataCalls = 0; $script:fixtureMetadataCase = $Name
    $accepted = $false
    try { Measure-Tree $owned $ActiveRoots | Out-Null; $accepted = $true }
    catch {
        $caughtCause = $_.Exception
        Write-FixtureRecord ($Name + '.caught.json') ([ordered]@{
            caught_types = Get-FixtureExceptionTypes $caughtCause
            entry_depth = $script:fixtureMetadataDepth
            active_root_count = $script:fixtureMetadataRootCount
            transient_root_selected = $script:fixtureMetadataRootSelected
            caught_absence_classified = Test-TransientMissingException $caughtCause
        })
        if ($Allowed -or -not (Test-TransientMissingException $caughtCause)) { throw }
    }
    if ($accepted -ne $Allowed -or $script:fixtureMetadataCalls -ne 1 -or
        $script:fixtureMetadataDepth -ne $ExpectedDepth -or $script:fixtureMetadataRootCount -ne $ActiveRoots.Count -or
        $script:fixtureMetadataRootSelected -ne $Allowed) { throw ('Metadata race boundary failed: ' + $Name) }
    $cases.Add($Name)
}
Check-MetadataRace 'active-enumerated-cache-leaf' $leaf ([string[]]@($cache)) $true 5
Check-MetadataRace 'completed-cache-leaf' $leaf ([string[]]@()) $false 5
Check-MetadataRace 'owner-record-outside-active-roots' ([System.IO.Path]::Combine($owned,'owner.json')) ([string[]]@($cache)) $false 1
$script:fixtureMetadataPath = $null
try { Assert-TransientMissingBoundary ([System.IO.Path]::Combine($owned,'unknown','missing')) $cache; throw 'Unknown root was accepted.' }
catch { if ($_.Exception.Message -cne 'Physical managed path escaped its owned parent.') { throw } }
$cases.Add('unknown-root-rejected')
try { Assert-TransientMissingBoundary $cache $cache; throw 'Fixed root absence was accepted.' }
catch { if ($_.Exception.Message -cne 'Physical managed path escaped its owned parent.') { throw } }
$cases.Add('fixed-root-rejected')
$fileParent = [System.IO.Path]::Combine($cache,'regular-file-parent')
[System.IO.File]::WriteAllBytes($fileParent,[byte[]]@(7))
try { Assert-TransientMissingBoundary ([System.IO.Path]::Combine($fileParent,'missing')) $cache; throw 'Regular-file ancestor was accepted.' }
catch { if ($_.Exception.Message -cne 'Transient observation ancestry changed file type.') { throw } }
$cases.Add('surviving-regular-file-ancestor-rejected')
$outside = Assert-Directory ([System.IO.Path]::Combine($evidence,'outside-fixture')) $true
$sentinel = [System.IO.Path]::Combine($outside,'keep')
[System.IO.File]::WriteAllBytes($sentinel,[byte[]]@(8,9))
$junction = [System.IO.Path]::Combine($cache,'junction-fixture')
Assert-Within $junction $cache
New-Item -ItemType Junction -Path $junction -Target $outside -ErrorAction Stop | Out-Null
try { Assert-TransientMissingBoundary ([System.IO.Path]::Combine($junction,'missing')) $cache; throw 'Junction ancestor was accepted.' }
catch { if ($_.Exception.Message -cne 'Transient observation ancestry contains a link.') { throw } }
if (([System.IO.File]::GetAttributes($junction) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'Fixture junction identity changed.' }
if ([Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($cache).ToLowerInvariant() -cne $observationIdentities[$cache] -or
    [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($junction) -cne [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($outside)) {
    throw 'Fixture junction ownership or target changed; authored link is preserved.'
}
# Remove only this authored link, with a nonrecursive directory operation. Its
# external target and sentinel remain available for verification and diagnosis.
[System.IO.Directory]::Delete($junction,$false)
if ([System.Convert]::ToHexString([System.IO.File]::ReadAllBytes($sentinel)) -cne '0809') { throw 'Fixture junction target changed.' }
$cases.Add('surviving-junction-ancestor-rejected')
$receipt = [ordered]@{schema='mmmm-bootstrap-observation-result/1';token=$fixtureToken;case_count=$cases.Count;cases=$cases.ToArray();passed=$true;fixture_preserved=$true}
Write-FixtureRecord 'observation-result.json' $receipt
$receipt | ConvertTo-Json -Depth 6 -Compress
