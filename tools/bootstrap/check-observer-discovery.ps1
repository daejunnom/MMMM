# Pure regression checks for the observer's closed prespawn diagnostics. Import
# only these production functions; never run the launcher, filesystem lookup,
# vswhere, compiler selection or observer main from this fixture.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    ([System.IO.Path]::Combine($PSScriptRoot,'observer-ci.ps1')),[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Observer source did not parse.' }
foreach ($name in @('New-VswherePrespawnObservation','Update-VswherePrespawnObservation')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$false))
    if ($functions.Count -ne 1) { throw 'Fixture requires one exact prespawn function per name.' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$cases = [System.Collections.Generic.List[string]]::new()
$stages = @('prepare','program_files_physical','executable_physical','executable_open','executable_hash','spawn_prepare')
$initial = New-VswherePrespawnObservation
if ($initial.stage -cne 'prepare' -or $initial.elapsed_ms -ne 0 -or
    $initial.steps.prepare.started_ms -ne 0 -or $null -ne $initial.steps.prepare.completed_ms) {
    throw 'Prepare must start incomplete at the original clock origin.'
}
foreach ($stage in $stages | Select-Object -Skip 1) {
    if ($null -ne $initial.steps[$stage]) { throw 'An unstarted operation must remain null.' }
}
$cases.Add('unstarted-stages-null')

$elapsed = 1L
foreach ($stage in $stages) {
    if ($stage -cne 'prepare') {
        Update-VswherePrespawnObservation $initial $stage $elapsed $false
        if ($null -ne $initial.steps[$stage].completed_ms) { throw 'Starting an operation cannot complete it.' }
        $elapsed++
    }
    Update-VswherePrespawnObservation $initial $stage $elapsed $true
    if ($initial.steps[$stage].completed_ms -ne $elapsed) { throw 'Exact completion elapsed was not preserved.' }
    $elapsed++
}
if ($initial.stage -cne 'spawn_prepare' -or $initial.elapsed_ms -ne ($elapsed - 1)) { throw 'Ordered prespawn stages were not preserved.' }
$cases.Add('ordered-completions')

foreach ($expired in @(5000L,5001L)) {
    $observation = New-VswherePrespawnObservation
    try {
        Update-VswherePrespawnObservation $observation 'prepare' $expired $true
        throw 'Expired completion was accepted.'
    } catch { if ($_.Exception.Message -cne 'OBSERVER_VSWHERE_PRESPAWN_DEADLINE') { throw } }
    if ($observation.stage -cne 'prepare' -or $observation.elapsed_ms -ne $expired -or
        $observation.steps.prepare.completed_ms -ne $expired -or $null -ne $observation.steps.program_files_physical) {
        throw 'Expired completion must retain elapsed without starting the next operation.'
    }
}
$cases.Add('original-deadline-at-and-after-boundary')

$observation = New-VswherePrespawnObservation
Update-VswherePrespawnObservation $observation 'prepare' 4999L $true
try {
    Update-VswherePrespawnObservation $observation 'program_files_physical' 5000L $false
    throw 'An operation started at the expired deadline.'
} catch { if ($_.Exception.Message -cne 'OBSERVER_VSWHERE_PRESPAWN_DEADLINE') { throw } }
if ($observation.stage -cne 'prepare' -or $null -ne $observation.steps.program_files_physical) {
    throw 'A denied start cannot manufacture an operation result.'
}
$cases.Add('checkpoint-before-next-operation')

$observation = New-VswherePrespawnObservation
Update-VswherePrespawnObservation $observation 'prepare' 100L $true
Update-VswherePrespawnObservation $observation 'program_files_physical' 101L $false
$decoded = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $observation -Depth 6 -Compress) -AsHashtable
if ($decoded.stage -cne 'program_files_physical' -or $decoded.steps.program_files_physical.started_ms -ne 101 -or
    $null -ne $decoded.steps.program_files_physical.completed_ms -or $null -ne $decoded.steps.executable_open) {
    throw 'A failed operation must round trip as incomplete, with future methods not run.'
}
$cases.Add('incomplete-method-nullable-round-trip')

foreach ($invalid in @('skip','repeat','backwards','negative','unknown')) {
    $observation = New-VswherePrespawnObservation
    Update-VswherePrespawnObservation $observation 'prepare' 10L $true
    try {
        switch ($invalid) {
            'skip' { Update-VswherePrespawnObservation $observation 'executable_open' 11L $false }
            'repeat' { Update-VswherePrespawnObservation $observation 'prepare' 11L $true }
            'backwards' { Update-VswherePrespawnObservation $observation 'program_files_physical' 9L $false }
            'negative' { Update-VswherePrespawnObservation $observation 'program_files_physical' -1L $false }
            'unknown' { Update-VswherePrespawnObservation $observation 'unlisted' 11L $false }
        }
        throw 'Invalid observation transition was accepted.'
    } catch {
        if ($invalid -ceq 'unknown') {
            if ($_.Exception -isnot [System.Management.Automation.ParameterBindingException] -or
                $_.Exception.GetType().FullName -cne 'System.Management.Automation.ParameterBindingValidationException') { throw }
        } elseif ($_.Exception.Message -cne 'OBSERVER_VSWHERE_PRESPAWN_OBSERVATION_INVALID') { throw }
    }
}
$cases.Add('closed-stages-and-monotonic-transitions')
[ordered]@{schema='mmmm-observer-discovery-check/1';case_count=$cases.Count;cases=$cases.ToArray();passed=$true} |
    ConvertTo-Json -Depth 4 -Compress
