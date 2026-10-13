# First Rust tool compilation on Windows. Later builds use the Rust managed runner.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Checkout,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$OutputRoot,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 1200,
    [ValidateRange(1, 2)][int]$Jobs = 2
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.2') {
    throw 'Bootstrap requires PowerShell Core 7.2 or later with the in-memory Add-Type compiler.'
}
if (-not $IsWindows) { throw 'This bootstrap entry point supports Windows only.' }

$schema = 'mmmm-managed-build/1'
$recordLimit = 8192
$slotLimit = [uint64](8GB)
$catalogLimit = [uint64](12GB)
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)

function Assert-SafeName([string]$Name) {
    $lower = $Name.ToLowerInvariant()
    $marker = @('credential','service-account','service_account','api-key','api_key') | Where-Object { $lower.Contains($_) }
    $suffix = @('.json','.toml','.yaml','.yml','.pem','.key') | Where-Object { $lower.EndsWith($_) }
    if ($lower -eq '.env' -or $lower.StartsWith('.env.') -or $lower -eq '.ssh' -or
        $lower -in @('id_rsa', 'id_ed25519') -or ($marker -and $suffix)) {
        throw 'Secret-named paths are not inspected or managed.'
    }
}
function Assert-SafeRoot([string]$Path) {
    foreach ($piece in $Path.Split([char]'\', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        Assert-SafeName $piece
        $lower = $piece.ToLowerInvariant()
        foreach ($marker in @('credential','service-account','service_account','api-key','api_key')) {
            if ($lower.Contains($marker)) { throw 'Secret-named roots are not inspected or managed.' }
        }
    }
}
function Assert-SafeFile([string]$Path) {
    $name = [System.IO.Path]::GetFileName($Path)
    Assert-SafeName $name
    if ($name.ToLowerInvariant() -in @('credential','credentials','api-key','api_key','api-keys','api_keys','private-key')) { throw 'Secret-named regular files are not inspected or managed.' }
}
function Assert-Directory([string]$Path, [bool]$Create) {
    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) { throw 'An absolute path is required.' }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\')) { throw 'Network and device roots are not supported.' }
    $current = [System.IO.Path]::GetPathRoot($full)
    $pieces = $full.Substring($current.Length).Split([char]'\', [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($piece in $pieces) {
        Assert-SafeName $piece
        $current = [System.IO.Path]::Combine($current, $piece)
        if (-not [System.IO.Directory]::Exists($current)) {
            if (-not $Create -or [System.IO.File]::Exists($current)) { throw 'Directory ancestry is missing or changed file type.' }
            [System.IO.Directory]::CreateDirectory($current) | Out-Null
        }
        $attributes = [System.IO.File]::GetAttributes($current)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
            throw 'Directory ancestry contains a link or changed file type.'
        }
    }
    return $full.TrimEnd([char]'\')
}
function Assert-Separate([string]$First, [string]$Second) {
    $a = $First.TrimEnd([char]'\').ToLowerInvariant()
    $b = $Second.TrimEnd([char]'\').ToLowerInvariant()
    if ($a -eq $b -or $a.StartsWith($b + '\') -or $b.StartsWith($a + '\')) { throw 'Managed paths overlap.' }
}
function New-HexToken {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [System.Convert]::ToHexString($bytes).ToLowerInvariant()
}
function Test-HexDigest([string]$Value) { return $Value -cmatch '^[0-9a-f]{64}$' }
function Write-NewRecord([string]$Path, $Record) {
    Assert-SafeFile $Path
    Assert-Directory ([System.IO.Path]::GetDirectoryName($Path)) $false | Out-Null
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $Record -Depth 8 -Compress))
    if ($bytes.Length -gt $recordLimit) { throw 'Ownership record exceeds 8 KiB.' }
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Write-ReplacedRecord([string]$Path, $Record) {
    $temporary = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($Path), '.record-' + (New-HexToken) + '.tmp')
    Write-NewRecord $temporary $Record
    [System.IO.File]::Move($temporary, $Path, $true)
}
function Read-RecordBytes([string]$Path) {
    Assert-SafeFile $Path
    Assert-Directory ([System.IO.Path]::GetDirectoryName($Path)) $false | Out-Null
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band ([System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Directory)) -ne 0) { throw 'Ownership record is not a regular file.' }
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $recordLimit) { throw 'Ownership record exceeds 8 KiB.' }
        $buffer = [byte[]]::new($recordLimit + 1)
        $count = 0
        while ($count -lt $buffer.Length) {
            $read = $stream.Read($buffer, $count, $buffer.Length - $count)
            if ($read -eq 0) { break }; $count += $read
        }
        if ($count -gt $recordLimit) { throw 'Ownership record grew beyond its limit.' }
        $result = [byte[]]::new($count)
        [System.Array]::Copy($buffer, $result, $count)
    } finally { $stream.Dispose() }
    return ,$result
}
function Read-Record([string]$Path, [string[]]$Fields) {
    $json = $utf8.GetString((Read-RecordBytes $Path))
    $document = [System.Text.Json.JsonDocument]::Parse($json, [System.Text.Json.JsonDocumentOptions]::new())
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'Ownership record must be an object.' }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $document.RootElement.EnumerateObject()) {
            if (-not $seen.Add($property.Name) -or $property.Name -cnotin $Fields) { throw 'Duplicate or unknown ownership record field.' }
            $kind = $property.Value.ValueKind
            if ($property.Name -cin @('schema','catalog_id','slot_id','token','checkout_digest','os','arch','purpose')) {
                if ($kind -ne [System.Text.Json.JsonValueKind]::String) { throw 'Ownership identity must be a JSON string.' }
            } elseif ($property.Name -cin @('pid','started_ms','completed_ms')) {
                if ($property.Name -ceq 'completed_ms' -and $kind -eq [System.Text.Json.JsonValueKind]::Null) { continue }
                [uint64]$integer = 0
                if ($kind -ne [System.Text.Json.JsonValueKind]::Number -or -not $property.Value.TryGetUInt64([ref]$integer)) { throw 'Ownership time and process fields must be unsigned JSON integers.' }
                if ($property.Name -ceq 'pid' -and ($integer -eq 0 -or $integer -gt [uint32]::MaxValue)) { throw 'Ownership process identifier is outside u32 range.' }
            } elseif ($property.Name -ceq 'lease_released') {
                if ($kind -notin @([System.Text.Json.JsonValueKind]::True,[System.Text.Json.JsonValueKind]::False)) { throw 'Completion lease proof must be a JSON boolean.' }
            } elseif ($property.Name -ceq 'receipt') {
                if ($kind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'Completion receipt must be a JSON object.' }
            } elseif ($property.Name -ceq 'state') {
                if ($kind -ne [System.Text.Json.JsonValueKind]::String -or $property.Value.GetString() -cnotin @('active','complete')) { throw 'Unknown ownership state.' }
            }
        }
        if ($seen.Count -ne $Fields.Length) { throw 'Ownership record has missing fields.' }
    } finally { $document.Dispose() }
    return ConvertFrom-Json -InputObject $json -AsHashtable
}
function Assert-EntryNames([string]$Path, [string[]]$Names) {
    foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($Path)) {
        $name = [System.IO.Path]::GetFileName($entry)
        Assert-SafeName $name
        if ($name -cnotin $Names -or ([System.IO.File]::GetAttributes($entry) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Unknown entry or link in an owned root is preserved.'
        }
    }
}
function Measure-Tree([string]$Path) {
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push(@($Path, 0)); $count = 0; [uint64]$bytes = 0
    while ($pending.Count -gt 0) {
        $item = $pending.Pop(); $entry = [string]$item[0]; $depth = [int]$item[1]; $count++
        if ($depth -gt 64 -or $count -gt 100000) { throw 'Managed tree walk limit exceeded.' }
        Assert-SafeName ([System.IO.Path]::GetFileName($entry))
        $attributes = [System.IO.File]::GetAttributes($entry)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Bootstrap does not traverse links.' }
        if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            foreach ($child in [System.IO.Directory]::EnumerateFileSystemEntries($entry)) {
                if ($pending.Count + $count -ge 100000) { throw 'Managed tree entry limit exceeded.' }
                $pending.Push(@($child, $depth + 1))
            }
        } else {
            Assert-SafeFile $entry
            $length = [uint64]([System.IO.FileInfo]::new($entry).Length)
            if ($bytes -gt [uint64]::MaxValue - $length) { throw 'Managed tree size overflow.' }
            $bytes += $length
        }
    }
    return $bytes
}
function Assert-RecordBytes([string]$Path, [byte[]]$Expected) {
    $current = Read-RecordBytes $Path
    if ([System.Convert]::ToBase64String($current) -cne [System.Convert]::ToBase64String($Expected)) { throw 'Ownership record changed; slot and lease preserved.' }
}
function Complete-FailedBootstrap($Result, [bool]$Exported) {
    # This is callable only for the child observed by this live launcher invocation.
    # There is no input flag or stale-record path that can enter this finalizer.
    if ($null -eq $Result.CommandExit -or $Result.CommandExit -eq 0 -or -not $Result.Drained -or
        -not $Exported -or $Result.SupervisorErrors.Length -ne 0) { throw 'Failed bootstrap finalization lacks current-run drain/export proof.' }
    foreach ($path in @($catalogPath,$slotsPath,$slotPath,$scratch,$evidencePath)) { Assert-Directory $path $false | Out-Null }
    if ([Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($checkoutPath).ToLowerInvariant() -cne $checkoutIdentity -or
        [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($slotPath).ToLowerInvariant() -cne $slotPath.ToLowerInvariant()) { throw 'Failed bootstrap physical identity changed.' }
    Assert-RecordBytes $catalogFile $catalogBytes
    Assert-RecordBytes $leaseFile $leaseBytes
    Assert-RecordBytes $ownerFile $ownerBytes
    $freshLease = Read-Record $leaseFile @('schema','catalog_id','slot_id','token','pid','started_ms')
    $freshOwner = Read-Record $ownerFile @('schema','catalog_id','slot_id','checkout_digest','os','arch','purpose','token','pid','state','completed_ms')
    if ($freshLease.token -cne $token -or $freshLease.pid -ne $PID -or $freshOwner.token -cne $token -or
        $freshOwner.pid -ne $PID -or $freshOwner.state -cne 'active' -or $freshLease.slot_id -cne $slotId -or
        $freshOwner.slot_id -cne $slotId -or $freshOwner.checkout_digest -cne $checkoutDigest) { throw 'Failed bootstrap is outside current launcher ownership.' }
    $totalCompleted = 0
    foreach ($existing in [System.IO.Directory]::EnumerateDirectories($slotsPath)) {
        $fresh = Read-Record ([System.IO.Path]::Combine($existing,'owner.json')) @('schema','catalog_id','slot_id','checkout_digest','os','arch','purpose','token','pid','state','completed_ms')
        if ($fresh.state -ceq 'complete') { $totalCompleted++ }
        elseif ($fresh.slot_id -cne $slotId -or $fresh.token -cne $token) { throw 'Another active slot is preserved.' }
    }
    if ($totalCompleted -ge 4 -or (Measure-Tree $slotPath) -gt $slotLimit -or (Measure-Tree $catalogPath) -gt $catalogLimit) {
        throw 'Failed bootstrap cannot finalize within cache limits; slot and lease preserved.'
    }
    $failureReceipt = [ordered]@{ schema='mmmm-bootstrap-failed/1'; token=$token; slot_id=$slotId; command_exit=$Result.CommandExit; drained=$true; evidence_exported=$true; supervisor_errors=@(); scratch_preserved=$true; lease_released=$false }
    $failureFile = [System.IO.Path]::Combine($evidencePath,'bootstrap-failed.json')
    Write-NewRecord $failureFile $failureReceipt
    # Revalidate immediately before the only ownership mutation and lease deletion.
    Assert-RecordBytes $catalogFile $catalogBytes
    Assert-RecordBytes $leaseFile $leaseBytes
    Assert-RecordBytes $ownerFile $ownerBytes
    $completeOwner = [ordered]@{}
    foreach ($name in $owner.Keys) { $completeOwner[$name] = $owner[$name] }
    $completeOwner.state = 'complete'; $completeOwner.completed_ms = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Write-ReplacedRecord $ownerFile $completeOwner
    Assert-RecordBytes $ownerFile ($utf8.GetBytes((ConvertTo-Json -InputObject $completeOwner -Depth 8 -Compress)))
    Assert-RecordBytes $catalogFile $catalogBytes
    Assert-RecordBytes $leaseFile $leaseBytes
    [System.IO.File]::Delete($leaseFile)
    $failureReceipt.lease_released = $true
    Write-ReplacedRecord $failureFile $failureReceipt
}

# PowerShell Core compiles this small FFI bridge in memory. It creates no build tree.
Add-Type -Path ([System.IO.Path]::Combine($PSScriptRoot, 'WindowsBootstrap.cs'))
$checkoutPath = Assert-Directory $Checkout $false
$checkoutPath = [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($checkoutPath)
$checkoutIdentity = $checkoutPath.TrimEnd([char]'\').ToLowerInvariant()
$checkoutDigest = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($utf8.GetBytes($checkoutIdentity))).ToLowerInvariant()
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
$arch = switch ($architecture) { 'X64' { 'x86_64' } 'Arm64' { 'aarch64' } default { throw 'Unsupported Windows process architecture.' } }
$slotId = 'windows-' + $arch + '-' + $checkoutDigest.Substring(0, 24) + '-bootstrap'
if (-not $OutputRoot) {
    if ($env:RUNNER_TEMP) { $OutputRoot = [System.IO.Path]::Combine($env:RUNNER_TEMP, 'MMMM') }
    else { $OutputRoot = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('ApplicationData'), 'MMMM') }
}
Assert-SafeRoot $Checkout
Assert-SafeRoot $OutputRoot
Assert-SafeRoot $EvidenceRoot
if (-not [System.IO.Path]::IsPathFullyQualified($OutputRoot) -or -not [System.IO.Path]::IsPathFullyQualified($EvidenceRoot)) { throw 'Output and evidence roots must be absolute.' }
$outputRequested = [System.IO.Path]::GetFullPath($OutputRoot)
$evidenceRequested = [System.IO.Path]::GetFullPath($EvidenceRoot)
Assert-Separate $outputRequested $checkoutPath
Assert-Separate $evidenceRequested $checkoutPath
Assert-Separate ([System.IO.Path]::Combine($outputRequested,'build','managed-v1')) $evidenceRequested
$outputPath = Assert-Directory $outputRequested $true
$evidencePath = Assert-Directory $evidenceRequested $true
$catalogPath = [System.IO.Path]::Combine($outputPath, 'build', 'managed-v1')
$catalogPath = Assert-Directory $catalogPath $true
$catalogFile = [System.IO.Path]::Combine($catalogPath, 'catalog.json')
if (-not [System.IO.File]::Exists($catalogFile)) {
    if (@([System.IO.Directory]::EnumerateFileSystemEntries($catalogPath)).Count -ne 0) { throw 'Unowned nonempty catalog is preserved.' }
    Write-NewRecord $catalogFile ([ordered]@{ schema=$schema; catalog_id=(New-HexToken) })
}
$catalog = Read-Record $catalogFile @('schema', 'catalog_id')
$catalogBytes = Read-RecordBytes $catalogFile
if ($catalog.schema -cne $schema -or -not (Test-HexDigest $catalog.catalog_id)) { throw 'Unknown catalog identity.' }
Assert-EntryNames $catalogPath @('catalog.json', 'lease.json', 'slots')
$token = New-HexToken
$started = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$lease = [ordered]@{ schema=$schema; catalog_id=$catalog.catalog_id; slot_id=$slotId; token=$token; pid=$PID; started_ms=$started }
# CreateNew is the catalog lock. Existing and interrupted leases are never adopted.
$leaseFile = [System.IO.Path]::Combine($catalogPath, 'lease.json')
Write-NewRecord $leaseFile $lease
$leaseBytes = $utf8.GetBytes((ConvertTo-Json -InputObject $lease -Depth 8 -Compress))
$slotsPath = Assert-Directory ([System.IO.Path]::Combine($catalogPath, 'slots')) $true
$completed = 0
foreach ($existing in [System.IO.Directory]::EnumerateDirectories($slotsPath)) {
    Assert-Directory $existing $false | Out-Null
    $owner = Read-Record ([System.IO.Path]::Combine($existing, 'owner.json')) @('schema','catalog_id','slot_id','checkout_digest','os','arch','purpose','token','pid','state','completed_ms')
    $name = [System.IO.Path]::GetFileName($existing)
    if ($owner.schema -cne $schema -or $owner.catalog_id -cne $catalog.catalog_id -or $owner.slot_id -cne $name -or
        -not (Test-HexDigest $owner.checkout_digest) -or -not (Test-HexDigest $owner.token) -or $owner.pid -le 0 -or
        $owner.purpose -cnotmatch '^[a-z0-9-]{1,48}$' -or $owner.os -cnotin @('windows','linux','macos') -or
        $owner.arch -cnotin @('x86_64','aarch64') -or $owner.state -cne 'complete' -or $null -eq $owner.completed_ms -or
        ($owner.os + '-' + $owner.arch + '-' + $owner.checkout_digest.Substring(0,24) + '-' + $owner.purpose) -cne $name) {
        throw 'Interrupted or unrecognized existing slot is preserved.'
    }
    Assert-EntryNames $existing @('owner.json','cache','scratch')
    $existingCache = [System.IO.Path]::Combine($existing, 'cache')
    if ([System.IO.Directory]::Exists($existingCache)) { Assert-EntryNames $existingCache @('cargo-target','cargo-home','gradle-build','gradle-project-cache','gradle-user-home') }
    $completed++
}
if (@([System.IO.Directory]::EnumerateFiles($slotsPath)).Count -ne 0 -or $completed -gt 4) { throw 'Slot catalog has unknown entries or exceeds the completed-slot limit.' }
$slotPath = Assert-Directory ([System.IO.Path]::Combine($slotsPath, $slotId)) $true
$owner = [ordered]@{ schema=$schema; catalog_id=$catalog.catalog_id; slot_id=$slotId; checkout_digest=$checkoutDigest; os='windows'; arch=$arch; purpose='bootstrap'; token=$token; pid=$PID; state='active'; completed_ms=$null }
$ownerFile = [System.IO.Path]::Combine($slotPath, 'owner.json')
Write-ReplacedRecord $ownerFile $owner
$ownerBytes = $utf8.GetBytes((ConvertTo-Json -InputObject $owner -Depth 8 -Compress))
$cache = Assert-Directory ([System.IO.Path]::Combine($slotPath, 'cache')) $true
$target = Assert-Directory ([System.IO.Path]::Combine($cache, 'cargo-target')) $true
foreach ($name in @('gradle-build','gradle-project-cache','gradle-user-home')) { Assert-Directory ([System.IO.Path]::Combine($cache, $name)) $true | Out-Null }
$scratch = Assert-Directory ([System.IO.Path]::Combine($slotPath, 'scratch')) $true
$cargoHome = Assert-Directory ([System.IO.Path]::Combine($cache, 'cargo-home')) $true
$ownership = [ordered]@{ schema=$schema; catalog_id=$catalog.catalog_id; slot_id=$slotId; checkout_digest=$checkoutDigest; os='windows'; arch=$arch; purpose='bootstrap'; token=$token; pid=$PID; started_ms=$started }
$ownershipFile = [System.IO.Path]::Combine($evidencePath, 'bootstrap-ownership.json')
Write-NewRecord $ownershipFile $ownership
$savedEnvironment = @{}
foreach ($name in @('CARGO_TARGET_DIR','CARGO_HOME','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','TMP','TEMP')) { $savedEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process') }
foreach ($name in @('CARGO_TARGET_DIR','CARGO_HOME')) {
    $expected = if ($name -eq 'CARGO_TARGET_DIR') { $target } else { $cargoHome }
    if ($savedEnvironment[$name] -and [System.IO.Path]::GetFullPath($savedEnvironment[$name]) -ine $expected) { throw ('Conflicting managed override is rejected: ' + $name + '; lease preserved.') }
}
if ($null -ne $savedEnvironment.CARGO_INCREMENTAL -and $savedEnvironment.CARGO_INCREMENTAL -cne '0') { throw 'Conflicting CARGO_INCREMENTAL override is rejected; lease preserved.' }
$overrides = @{ CARGO_TARGET_DIR=$target; CARGO_HOME=$cargoHome; CARGO_BUILD_JOBS=[string]$Jobs; CARGO_INCREMENTAL='0'; TMP=$scratch; TEMP=$scratch }
$observe = [System.Func[string]]{
    try {
        Assert-Directory $catalogPath $false | Out-Null
        if ((Measure-Tree $slotPath) -gt $slotLimit) { return 'bootstrap slot byte budget exceeded' }
        if ((Measure-Tree $catalogPath) -gt $catalogLimit) { return 'bootstrap catalog byte budget exceeded' }
        return $null
    } catch { return 'bootstrap budget observation failed: ' + $_.Exception.Message }
}
try {
    foreach ($name in $overrides.Keys) { [System.Environment]::SetEnvironmentVariable($name, $overrides[$name], 'Process') }
    $preflight = $observe.Invoke(); if ($preflight) { throw $preflight }
    $cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop).Source
    $stdout = [System.IO.Path]::Combine($scratch, 'cargo-' + $token + '.stdout.log')
    $stderr = [System.IO.Path]::Combine($scratch, 'cargo-' + $token + '.stderr.log')
    $result = [Mmmm.Bootstrap.WindowsBoundary]::Run($cargo, [string[]]@('build','-p','mmmm-xtask','--jobs',[string]$Jobs), $checkoutPath, $stdout, $stderr, $TimeoutSeconds, $observe)
    $postflight = $observe.Invoke()
    if ($postflight) { $result.SupervisorErrors = [string[]]@($result.SupervisorErrors) + @($postflight) }
    $exported = $false
    if ($result.Drained -and [System.IO.File]::Exists($stdout) -and [System.IO.File]::Exists($stderr)) {
        $totalLogs = [System.IO.FileInfo]::new($stdout).Length + [System.IO.FileInfo]::new($stderr).Length
        if ($totalLogs -le 128MB) {
            [System.IO.File]::Copy($stdout, [System.IO.Path]::Combine($evidencePath,'cargo.stdout.log'), $false)
            [System.IO.File]::Copy($stderr, [System.IO.Path]::Combine($evidencePath,'cargo.stderr.log'), $false)
            $exported = $true
        }
    }
    $proof = [ordered]@{ schema='mmmm-bootstrap-process/1'; token=$token; command_exit=$result.CommandExit; drained=$result.Drained; evidence_exported=$exported; supervisor_errors=@($result.SupervisorErrors) }
    $proofFile = [System.IO.Path]::Combine($evidencePath,'bootstrap-process.json')
    Write-NewRecord $proofFile $proof
    if ($null -ne $result.CommandExit -and $result.CommandExit -ne 0 -and $result.Drained -and $exported -and $result.SupervisorErrors.Length -eq 0) {
        Complete-FailedBootstrap $result $exported
        throw ('Cargo bootstrap command failed with exit ' + $result.CommandExit + '; exact owned slot completed and lease released; exported evidence and cache preserved.')
    }
    if ($result.CommandExit -ne 0 -or -not $result.Drained -or -not $exported -or $result.SupervisorErrors.Length -ne 0) { throw 'Bootstrap build did not establish clean drain and export; slot and lease preserved.' }
    $tool = [System.IO.Path]::Combine($target,'debug','mmmm-xtask.exe')
    if (-not [System.IO.File]::Exists($tool)) { throw 'Built Rust tool is missing; slot and lease preserved.' }
    $completionArgs = [string[]]@('bootstrap-complete','--checkout',$checkoutPath,'--ownership',$ownershipFile,'--proof',$proofFile,'--evidence-root',$evidencePath,'--purpose','bootstrap','--output-root',$outputPath)
    $completion = [Mmmm.Bootstrap.WindowsBoundary]::Run($tool, $completionArgs, $checkoutPath,
        [System.IO.Path]::Combine($evidencePath,'bootstrap-complete.stdout.log'), [System.IO.Path]::Combine($evidencePath,'bootstrap-complete.stderr.log'), 60, $observe)
    if ($completion.CommandExit -ne 0 -or -not $completion.Drained -or $completion.SupervisorErrors.Length -ne 0) { throw 'Rust bootstrap completion failed; inspect retained receipts and ownership.' }
    $receipt = Read-Record ([System.IO.Path]::Combine($evidencePath,'bootstrap-complete.json')) @('schema','token','slot_id','lease_released','receipt')
    if ($receipt.schema -cne 'mmmm-bootstrap-complete/1' -or $receipt.token -cne $token -or $receipt.slot_id -cne $slotId -or $receipt.lease_released -ne $true -or
        [System.IO.File]::Exists([System.IO.Path]::Combine($catalogPath,'lease.json'))) { throw 'Rust completion receipt does not establish lease release.' }
    [ordered]@{ schema='mmmm-bootstrap-result/1'; slot_id=$slotId; command_exit=0; drained=$true; evidence_exported=$true; lease_released=$true } | ConvertTo-Json -Compress
} finally {
    foreach ($name in $savedEnvironment.Keys) { [System.Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
