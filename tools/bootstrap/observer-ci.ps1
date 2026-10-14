# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MMMM contributors
# CI infrastructure only. Reuse the completed JVM job's selected inputs; each
# native operation has its own Rust-managed owner and original evidence.
[CmdletBinding()]
param(
    [ValidateSet('verify','header')][string]$Action = 'verify',
    [Parameter(Mandatory)][string]$Checkout,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceSha,
    [Parameter(Mandatory)][ValidateSet('windows-x64','linux-x64','macos-arm64')][string]$Target,
    [string]$OutputRoot,
    [string]$JvmEvidenceRoot,
    [string]$Xtask,
    [string]$Cargo,
    [string]$RustTarget,
    [string]$ManagedSlotRoot,
    [string]$JdkRoot,
    # The image README and the actual runner image can differ. An explicit
    # root is validated as given; otherwise query the installed VC component.
    [string]$WindowsVsRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$comparison = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
$phase = 'preflight'
$evidence = $null
$result = [ordered]@{
    schema='mmmm-observer-ci-result/1'; source_sha=$ExpectedSourceSha; target=$Target;
    rust_target=$RustTarget; status='not_run'; phase=$phase; failure=$null;
    jvm_verification='prior_record_required'; native_build='not_run'; header_witness='not_run';
    definition_startup='not_run'; source_manifest_sha256=$null; input_pins=@(); steps=@();
    scope='development_fixture'; source_admission_granted=$false; target_policy_granted=$false;
    whole_jdk_image_verified=$false; game_verification='not_run'; release_verification='not_run'
}
$stepRecords = [System.Collections.Generic.List[object]]::new()

function Assert-Physical([string]$Path, [bool]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathFullyQualified($Path)) { throw 'OBSERVER_ABSOLUTE_PATH_REQUIRED' }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($IsWindows -and ($full.StartsWith('\\') -or $full -cnotmatch '^[A-Za-z]:\\')) { throw 'OBSERVER_LOCAL_DOS_PATH_REQUIRED' }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'OBSERVER_PHYSICAL_PATH_REQUIRED' }
    $cursor = if ($Directory) { $full } else { [System.IO.Path]::GetDirectoryName($full) }
    while ($cursor) {
        $ancestor = Get-Item -LiteralPath $cursor -Force
        if (-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'OBSERVER_PHYSICAL_ANCESTRY_REQUIRED' }
        $next = [System.IO.Path]::GetDirectoryName($cursor)
        if ($next -eq $cursor) { break }
        $cursor = $next
    }
    return $full
}

function Is-Inside([string]$Path, [string]$Root) {
    return $Path.Equals($Root, $comparison) -or $Path.StartsWith($Root.TrimEnd('/','\') + [System.IO.Path]::DirectorySeparatorChar, $comparison)
}

function New-Directory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'OBSERVER_EVIDENCE_ALREADY_EXISTS' }
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    return Assert-Physical $Path $true
}

function Get-Hash([string]$Path, [long]$Limit) {
    $full = Assert-Physical $Path $false
    $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $Limit) { throw 'OBSERVER_INPUT_BUDGET' }
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    } finally { $stream.Dispose() }
}

function Read-Json([string]$Path, [long]$Limit = 65536) {
    $null = Get-Hash $Path $Limit
    return ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path, $utf8)) -AsHashtable
}

function Write-NewJson([string]$Path, $Value, [long]$Limit = 1048576) {
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 20 -Compress))
    if ($bytes.Length -gt $Limit) { throw 'OBSERVER_RESULT_BUDGET' }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Failure-Shape([System.Exception]$Exception) {
    $chain = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $null -ne $Exception -and $index -lt 8; $index++) {
        $type = $Exception.GetType().FullName
        if ($type -cnotmatch '^[A-Za-z0-9_.+`]{1,192}$') { $type = 'withheld' }
        $code = if ($Exception.Message -cmatch '^OBSERVER_[A-Z0-9_]{1,96}$') { $Exception.Message } else { $null }
        $native = if ($Exception -is [System.ComponentModel.Win32Exception]) { $Exception.NativeErrorCode } else { $null }
        $chain.Add([ordered]@{ type=$type; hresult=$Exception.HResult; native_code=$native; static_code=$code })
        $Exception = $Exception.InnerException
    }
    return [ordered]@{ phase=$phase; exceptions=$chain.ToArray(); chain_truncated=($null -ne $Exception) }
}

function New-VswherePrespawnObservation {
    return [ordered]@{
        stage='prepare'; elapsed_ms=0L;
        steps=[ordered]@{
            prepare=[ordered]@{ started_ms=0L; completed_ms=$null };
            program_files_physical=$null; executable_physical=$null;
            executable_open=$null; executable_hash=$null; spawn_prepare=$null
        }
    }
}

function Update-VswherePrespawnObservation(
    [System.Collections.IDictionary]$Observation,
    [ValidateSet('prepare','program_files_physical','executable_physical','executable_open','executable_hash','spawn_prepare')][string]$Stage,
    [long]$ElapsedMilliseconds,
    [bool]$Completed
) {
    if ($ElapsedMilliseconds -lt 0 -or $ElapsedMilliseconds -lt $Observation.elapsed_ms) { throw 'OBSERVER_VSWHERE_PRESPAWN_OBSERVATION_INVALID' }
    $Observation.elapsed_ms = $ElapsedMilliseconds
    if ($Completed) {
        if ($Stage -cne $Observation.stage -or $null -eq $Observation.steps[$Stage] -or
            $null -ne $Observation.steps[$Stage].completed_ms) { throw 'OBSERVER_VSWHERE_PRESPAWN_OBSERVATION_INVALID' }
        $Observation.steps[$Stage].completed_ms = $ElapsedMilliseconds
    } else {
        $stages = @('prepare','program_files_physical','executable_physical','executable_open','executable_hash','spawn_prepare')
        $previous = [System.Array]::IndexOf($stages, $Observation.stage)
        $next = [System.Array]::IndexOf($stages, $Stage)
        if ($next -ne ($previous + 1) -or $null -eq $Observation.steps[$Observation.stage].completed_ms -or
            $null -ne $Observation.steps[$Stage]) { throw 'OBSERVER_VSWHERE_PRESPAWN_OBSERVATION_INVALID' }
        # A checkpoint cannot turn an expired operation into permission to
        # start its successor. The unstarted step stays null in the receipt.
        if ($ElapsedMilliseconds -ge 5000) { throw 'OBSERVER_VSWHERE_PRESPAWN_DEADLINE' }
        $Observation.stage = $Stage
        $Observation.steps[$Stage] = [ordered]@{ started_ms=$ElapsedMilliseconds; completed_ms=$null }
    }
    if ($ElapsedMilliseconds -ge 5000) { throw 'OBSERVER_VSWHERE_PRESPAWN_DEADLINE' }
}

function Find-InstalledVisualStudio {
    # Official installation/component selector and pipe encoding:
    # https://github.com/microsoft/vswhere/wiki/Find-VC
    # https://github.com/microsoft/vswhere/wiki/Encoding
    # This process remains a child of the existing 180-second managed owner.
    # Only its held Process handle is terminated here. Descendant containment
    # and final drain remain factual responsibilities of that outer owner.
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $prespawn = New-VswherePrespawnObservation
    $arguments = @('-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath','-utf8')
    $record = [ordered]@{
        schema='mmmm-observer-vswhere-discovery/1'; source_sha=$ExpectedSourceSha; target=$Target;
        status='failed'; phase='vswhere_prepare'; program=[ordered]@{ role='installed_vswhere'; bytes=$null; sha256=$null; revalidated=$false };
        argv=$arguments; argv_sha256=[System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($utf8.GetBytes((ConvertTo-Json -InputObject $arguments -Compress)))).ToLowerInvariant();
        limits=[ordered]@{ work_ms=5000; cleanup_ms=2500; stdout_bytes=4096; stderr_bytes=4096 };
        process_started=$false; command_exit=$null; root_exited=$false; root_exit_verified=$false;
        pipes_complete=$false; output_complete=$false; termination_attempted=$false; stop_reason=$null;
        stdout_bytes=0L; stderr_bytes=0L; stdout_sha256=$null; stderr_sha256=$null;
        stdout_limit_exceeded=$false; stderr_limit_exceeded=$false;
        selected_root_checked=$false; installation_path_bytes=$null; installation_path_sha256=$null;
        elapsed_ms=0L; failure=$null; secondary_failures=@(); descendant_drain='external_managed_owner_required';
        receipt_export='external_managed_deadline';
        whole_toolchain_image_verified=$false; prespawn=$prespawn
    }
    $process = [System.Diagnostics.Process]::new()
    $cancel = [System.Threading.CancellationTokenSource]::new()
    $heldProgram = $null
    $pumps = @()
    $selectedRoot = $null
    $originalFailure = $null
    $cleanupDeadline = $null
    try {
        $script:phase = 'vswhere_prepare'
        Update-VswherePrespawnObservation $prespawn 'prepare' $clock.ElapsedMilliseconds $true
        $script:phase = 'vswhere_program_files'
        Update-VswherePrespawnObservation $prespawn 'program_files_physical' $clock.ElapsedMilliseconds $false
        $programFiles = Assert-Physical ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86)) $true
        Update-VswherePrespawnObservation $prespawn 'program_files_physical' $clock.ElapsedMilliseconds $true
        $script:phase = 'vswhere_executable'
        Update-VswherePrespawnObservation $prespawn 'executable_physical' $clock.ElapsedMilliseconds $false
        $program = Assert-Physical (Join-Path $programFiles 'Microsoft Visual Studio/Installer/vswhere.exe') $false
        Update-VswherePrespawnObservation $prespawn 'executable_physical' $clock.ElapsedMilliseconds $true
        Update-VswherePrespawnObservation $prespawn 'executable_open' $clock.ElapsedMilliseconds $false
        $heldProgram = [System.IO.File]::Open($program, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        Update-VswherePrespawnObservation $prespawn 'executable_open' $clock.ElapsedMilliseconds $true
        Update-VswherePrespawnObservation $prespawn 'executable_hash' $clock.ElapsedMilliseconds $false
        if ($heldProgram.Length -le 0 -or $heldProgram.Length -gt 16777216) { throw 'OBSERVER_VSWHERE_EXECUTABLE_BUDGET' }
        $record.program.bytes = $heldProgram.Length
        $record.program.sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($heldProgram)).ToLowerInvariant()
        Update-VswherePrespawnObservation $prespawn 'executable_hash' $clock.ElapsedMilliseconds $true
        $script:phase = 'vswhere_spawn'
        Update-VswherePrespawnObservation $prespawn 'spawn_prepare' $clock.ElapsedMilliseconds $false
        $info = [System.Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $program; $info.WorkingDirectory = $headerSlot
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
        $process.StartInfo = $info
        Update-VswherePrespawnObservation $prespawn 'spawn_prepare' $clock.ElapsedMilliseconds $true
        if (-not $process.Start()) { throw 'OBSERVER_VSWHERE_PROCESS_START_FAILED' }
        $record.process_started = $true
        $process.StandardInput.Close()
        $pumps = @(
            [pscustomobject]@{ name='stdout'; source=$process.StandardOutput.BaseStream; buffer=[byte[]]::new(1024); output=[System.IO.MemoryStream]::new(); task=$null; done=$false; overflow=$false },
            [pscustomobject]@{ name='stderr'; source=$process.StandardError.BaseStream; buffer=[byte[]]::new(1024); output=[System.IO.MemoryStream]::new(); task=$null; done=$false; overflow=$false }
        )
        foreach ($pump in $pumps) { $pump.task = $pump.source.ReadAsync($pump.buffer, 0, $pump.buffer.Length, $cancel.Token) }
        $script:phase = 'vswhere_capture'
        $stopHandled = $false
        while ($true) {
            foreach ($pump in $pumps) {
                if (-not $pump.done -and -not $pump.overflow -and $pump.task.IsCompleted) {
                    $read = $pump.task.GetAwaiter().GetResult()
                    if ($read -eq 0) { $pump.done = $true; continue }
                    if ($pump.output.Length + $read -gt 4096) {
                        $pump.overflow = $true
                        if ($null -eq $record.stop_reason) { $record.stop_reason = 'output_limit' }
                    } else {
                        $pump.output.Write($pump.buffer, 0, $read)
                        $pump.task = $pump.source.ReadAsync($pump.buffer, 0, $pump.buffer.Length, $cancel.Token)
                    }
                }
            }
            $record.root_exited = $process.HasExited
            if ($record.root_exited) { $record.command_exit = $process.ExitCode; $record.root_exit_verified = $true }
            $record.pipes_complete = $pumps[0].done -and $pumps[1].done
            if ($clock.ElapsedMilliseconds -ge 5000 -and $null -eq $record.stop_reason) { $record.stop_reason = 'deadline' }
            if ($null -ne $record.stop_reason -and -not $stopHandled) {
                $stopHandled = $true
                $cleanupDeadline = [Math]::Min(7500L, $clock.ElapsedMilliseconds + 2500L)
                if (-not $record.root_exited) {
                    $record.termination_attempted = $true
                    try { $process.Kill() }
                    catch { $record.secondary_failures += Failure-Shape $_.Exception }
                }
            }
            if ($record.root_exited -and $record.pipes_complete) { break }
            if ($null -ne $cleanupDeadline -and $clock.ElapsedMilliseconds -ge $cleanupDeadline) { break }
            [System.Threading.Thread]::Sleep(5)
        }
        $record.output_complete = $record.pipes_complete -and $null -eq $record.stop_reason
        if (-not $record.root_exit_verified -or $record.command_exit -ne 0 -or -not $record.output_complete) { throw 'OBSERVER_VSWHERE_NATIVE_COMPLETION_FAILED' }
        $script:phase = 'vswhere_output_frame'
        # Do not print or persist the installation pathname. Strict decoding
        # accepts one nonempty line and one ordinary terminal newline only.
        $stdoutText = $utf8.GetString($pumps[0].output.ToArray())
        $stderrText = $utf8.GetString($pumps[1].output.ToArray())
        if ($stderrText.Length -ne 0 -or $stdoutText -cnotmatch '\A[A-Za-z]:\\[^\x00-\x1f\x7f]+\r?\n\z') { throw 'OBSERVER_VSWHERE_OUTPUT_FRAME' }
        $candidate = $stdoutText.TrimEnd([char[]]@("`r","`n"))
        if ($candidate -cne $candidate.Trim() -or $candidate.Contains('"')) { throw 'OBSERVER_VSWHERE_OUTPUT_FRAME' }
        $script:phase = 'vswhere_installation_root'
        $selectedRoot = Assert-Physical $candidate $true
        $record.selected_root_checked = $true
        $pathBytes = $utf8.GetBytes($selectedRoot)
        $record.installation_path_bytes = $pathBytes.Length
        $record.installation_path_sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($pathBytes)).ToLowerInvariant()
        $script:phase = 'vswhere_input_revalidation'
        $heldProgram.Position = 0
        if ($heldProgram.Length -ne $record.program.bytes -or
            [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($heldProgram)).ToLowerInvariant() -cne $record.program.sha256 -or
            (Get-Hash $program 16777216) -cne $record.program.sha256) { throw 'OBSERVER_VSWHERE_EXECUTABLE_CHANGED' }
        $record.program.revalidated = $true
        if ($clock.ElapsedMilliseconds -ge 5000) { throw 'OBSERVER_VSWHERE_TOTAL_WORK_DEADLINE' }
        $record.status = 'passed'
    } catch {
        $originalFailure = $_.Exception
        $record.failure = Failure-Shape $originalFailure
    } finally {
        if (-not $record.process_started) {
            # Snapshot a failed synchronous stage without completing it or
            # claiming that a native method which was never run succeeded.
            $prespawn.elapsed_ms = $clock.ElapsedMilliseconds
        }
        # Failure before the normal wait loop still needs an actual bounded
        # root-process exit observation. Never enumerate PIDs or kill a tree.
        if ($record.process_started -and -not $record.root_exit_verified) {
            try {
                if ($null -eq $cleanupDeadline) { $cleanupDeadline = [Math]::Min(7500L, $clock.ElapsedMilliseconds + 2500L) }
                if (-not $process.HasExited) { $record.termination_attempted = $true; $process.Kill() }
                while (-not $process.HasExited -and $clock.ElapsedMilliseconds -lt $cleanupDeadline) { [System.Threading.Thread]::Sleep(5) }
                if ($process.HasExited) { $record.root_exited = $true; $record.command_exit = $process.ExitCode; $record.root_exit_verified = $true }
            } catch { $record.secondary_failures += Failure-Shape $_.Exception }
        }
        $cancel.Cancel()
        foreach ($pump in $pumps) {
            $record[$pump.name + '_bytes'] = $pump.output.Length
            $record[$pump.name + '_limit_exceeded'] = $pump.overflow
            $record[$pump.name + '_sha256'] = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($pump.output.ToArray())).ToLowerInvariant()
            $pump.output.Dispose()
        }
        if ($null -ne $heldProgram) { $heldProgram.Dispose() }
        $process.Dispose(); $cancel.Dispose()
        $record.phase = $phase; $record.elapsed_ms = $clock.ElapsedMilliseconds
        # This immutable receipt describes the completed discovery/cleanup.
        # Its file export remains under the original outer managed deadline.
        if ($clock.ElapsedMilliseconds -ge 7500 -and $null -eq $originalFailure) {
            $originalFailure = [System.InvalidOperationException]::new('OBSERVER_VSWHERE_FINALIZATION_DEADLINE')
            $record.status = 'failed'; $record.failure = Failure-Shape $originalFailure
        }
        try { Write-NewJson (Join-Path $evidence 'observer-vswhere-discovery.json') $record 65536 }
        catch { if ($null -eq $originalFailure) { $originalFailure = $_.Exception }; $record.status = 'failed' }
    }
    if ($null -ne $originalFailure) { throw $originalFailure }
    if ($record.status -cne 'passed') { throw 'OBSERVER_VSWHERE_DISCOVERY_FAILED' }
    return $selectedRoot
}

function Test-RecordFields($Record, [string[]]$Names) {
    if ($Record -isnot [System.Collections.IDictionary]) { return $false }
    foreach ($name in $Names) { if (-not $Record.Contains($name)) { return $false } }
    return $true
}

function Test-NullableInt32($Value) {
    return $null -eq $Value -or (($Value -is [int] -or $Value -is [long]) -and $Value -ge [int]::MinValue -and $Value -le [int]::MaxValue)
}

function Get-ProcessPayloadKind($Record) {
    $outcomeFields = @('command_exit','command_signal','supervisor_errors','drained','termination_reason','elapsed_ms',
        'stdout_bytes','stderr_bytes','output_complete','owned_tail_terminated','native_scope','resource_policy')
    if ((Test-RecordFields $Record $outcomeFields) -and -not $Record.Contains('kind')) {
        $numeric = $true
        foreach ($name in @('elapsed_ms','stdout_bytes','stderr_bytes')) {
            $value = $Record[$name]
            if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [ulong]) -or $value -lt 0) { $numeric = $false }
        }
        if ((Test-NullableInt32 $Record.command_exit) -and (Test-NullableInt32 $Record.command_signal) -and
            $Record.supervisor_errors -is [array] -and $Record.drained -is [bool] -and $Record.output_complete -is [bool] -and
            $Record.owned_tail_terminated -is [bool] -and $Record.termination_reason -is [string] -and
            $Record.termination_reason -cmatch '^[a-z][a-z0-9_]{0,95}$' -and $Record.native_scope -is [string] -and
            $Record.native_scope -cmatch '^[a-z][a-z0-9_]{0,95}$' -and $Record.resource_policy -is [string] -and
            $Record.resource_policy -cmatch '^[a-z][a-z0-9_./-]{0,95}$' -and $numeric) { return 'process_outcome' }
    }
    if ((Test-RecordFields $Record @('kind','native_os_code','process_error','storage_error','post_check_error')) -and
        $Record.kind -is [string] -and $Record.kind -cmatch '^[A-Z][A-Z0-9_]{0,95}$' -and
        (Test-NullableInt32 $Record.native_os_code)) { return 'startup_error' }
    if ((Test-RecordFields $Record @('kind','message','drained')) -and $Record.kind -is [string] -and
        $Record.kind -cmatch '^[A-Za-z][A-Za-z0-9_]{0,95}$' -and $Record.message -is [string] -and
        $Record.drained -is [bool]) { return 'supervisor_error' }
    return 'unrecognized'
}

function Get-ManagedRecords([string]$Root, [string]$Purpose) {
    $rootPath = Assert-Physical $Root $true
    # Enumerate only this invocation's dedicated evidence directories, never a
    # cache, toolchain, product store or general generated tree.
    $slotEntries = @(Get-ChildItem -LiteralPath $rootPath -Directory -Force)
    if ($slotEntries.Count -ne 1 -or $slotEntries[0].Name -cnotmatch ('^' + [regex]::Escape($hostPrefix) + '-[0-9a-f]{24}-' + [regex]::Escape($Purpose) + '$')) { throw 'OBSERVER_MANAGED_SLOT_RECORD_REQUIRED' }
    if ($slotEntries[0].Name -cne "$hostPrefix-$($checkoutDigest.Substring(0,24))-$Purpose") { throw 'OBSERVER_MANAGED_CHECKOUT_SLOT_MISMATCH' }
    $slotPath = Assert-Physical $slotEntries[0].FullName $true
    $tokens = @(Get-ChildItem -LiteralPath $slotPath -Directory -Force)
    if ($tokens.Count -ne 1 -or $tokens[0].Name -cnotmatch '^[0-9a-f]{64}$') { throw 'OBSERVER_MANAGED_TOKEN_RECORD_REQUIRED' }
    $recordRoot = Assert-Physical $tokens[0].FullName $true
    $finish = Read-Json (Join-Path $recordRoot 'finish.json')
    $process = Read-Json (Join-Path $recordRoot 'process.json') 262144
    $finalization = Read-Json (Join-Path $recordRoot 'finalization-input.json')
    if ($finish.schema -cne 'mmmm-managed-build/1' -or $finish.slot_id -cne $slotEntries[0].Name -or
        $finalization.schema -cne 'mmmm-build-finalization-input/1') { throw 'OBSERVER_MANAGED_RECORD_SCHEMA' }
    if ($finish.slot_evicted -ne $false) { throw 'OBSERVER_SELECTED_SLOT_EVICTED' }
    $ownerPath = Join-Path $slotsRoot "$($slotEntries[0].Name)/owner.json"
    $owner = Read-Json $ownerPath 8192
    if ($owner.schema -cne 'mmmm-managed-build/1' -or $owner.catalog_id -cne $catalog.catalog_id -or
        $owner.slot_id -cne $slotEntries[0].Name -or $owner.checkout_digest -cne $checkoutDigest -or
        $owner.os -cne $hostOS -or $owner.arch -cne $hostArch -or $owner.purpose -cne $Purpose -or
        $owner.token -cne $tokens[0].Name -or $owner.state -cne 'complete' -or $owner.completed_ms -eq $null) { throw 'OBSERVER_MANAGED_OWNER_MISMATCH' }
    $payloadKind = Get-ProcessPayloadKind $process
    $observation = $null; $observationSha = $null; $processStarted = $null; $candidatePresent = $null; $startupErrorKind = $null
    if ($Purpose -ceq 'definition-startup') {
        # Only this same owned observation records actual creation. A missing
        # native outcome is not evidence that no process was created.
        $observationPath = Join-Path $recordRoot 'definition-startup.json'
        $observation = Read-Json $observationPath 262144
        $observationSha = Get-Hash $observationPath 262144
        if (-not (Test-RecordFields $observation @('schema','scope','status','process_started')) -or
            $observation.schema -isnot [string] -or $observation.scope -isnot [string] -or $observation.status -isnot [string] -or
            $observation.schema -cne 'mmmm-definition-startup-observation/1' -or $observation.scope -cne 'development_fixture' -or
            $observation.status -cnotin @('observed','failed') -or
            ($null -ne $observation.process_started -and $observation.process_started -isnot [bool])) { throw 'OBSERVER_DEFINITION_OBSERVATION_INVALID' }
        $processStarted = $observation.process_started
        if ($observation.status -ceq 'failed') {
            if (-not (Test-RecordFields $observation @('error','raw_candidate_present')) -or
                -not (Test-RecordFields $observation.error @('kind')) -or $observation.error.kind -isnot [string] -or
                $observation.error.kind -cnotmatch '^[A-Z][A-Z0-9_]{0,95}$' -or
                $observation.raw_candidate_present -isnot [bool]) { throw 'OBSERVER_DEFINITION_OBSERVATION_INVALID' }
            $startupErrorKind = $observation.error.kind
            $candidatePresent = $observation.raw_candidate_present
        } elseif (-not (Test-RecordFields $observation @('raw_sha256')) -or $observation.raw_sha256 -isnot [string]) { throw 'OBSERVER_DEFINITION_OBSERVATION_INVALID' }
    }
    return [pscustomobject]@{ root=$recordRoot; slot_id=$slotEntries[0].Name; token=$tokens[0].Name; owner_sha256=(Get-Hash $ownerPath 8192);
        finish=$finish; process=$process; finalization=$finalization; process_payload_kind=$payloadKind;
        observation=$observation; observation_sha256=$observationSha; process_started=$processStarted;
        startup_error_kind=$startupErrorKind; raw_candidate_present=$candidatePresent }
}

function Assert-ManagedSuccess($Records, [bool]$AllowBuildTail = $false) {
    # Error DTOs, unknown payloads and incomplete outcomes can be recorded, but
    # never enter the native-success predicate or its full-outcome accesses.
    if ($Records.process_payload_kind -cne 'process_outcome' -or
        (Get-ProcessPayloadKind $Records.process) -cne 'process_outcome') { throw 'OBSERVER_MANAGED_PROCESS_OUTCOME_REQUIRED' }
    $nativeCompletion = ($Records.process.termination_reason -ceq 'completed' -and $Records.process.owned_tail_terminated -eq $false)
    if ($AllowBuildTail -and $Records.process.termination_reason -ceq 'completed_after_owned_tail_cleanup' -and
        $Records.process.owned_tail_terminated -eq $true) { $nativeCompletion = $true }
    if ($Records.finish.command_exit -ne 0 -or $Records.finish.lease_released -ne $true -or $Records.finish.scratch_removed -ne $true -or
        @($Records.finish.supervisor_errors).Count -ne 0 -or @($Records.finish.cleanup_errors).Count -ne 0 -or
        $Records.finalization.command_exit -ne 0 -or $Records.finalization.drained -ne $true -or $Records.finalization.evidence_exported -ne $true -or
        @($Records.finalization.supervisor_errors).Count -ne 0 -or $Records.process.command_exit -ne 0 -or $Records.process.command_signal -ne $null -or
        $Records.process.drained -ne $true -or $Records.process.output_complete -ne $true -or -not $nativeCompletion -or
        @($Records.process.supervisor_errors).Count -ne 0) { throw 'OBSERVER_MANAGED_SUCCESS_NOT_ESTABLISHED' }
}

function Add-ManagedStep([string]$Name, [string]$RelativeRoot, [int]$Exit, $Records) {
    $payloadKind = Get-ProcessPayloadKind $Records.process
    $termination = $null; $tailTerminated = $null; $processExit = $null; $processSignal = $null; $processDrained = $null; $outputComplete = $null
    if ($payloadKind -ceq 'process_outcome') {
        $termination = $Records.process.termination_reason; $tailTerminated = $Records.process.owned_tail_terminated
        $processExit = $Records.process.command_exit; $processSignal = $Records.process.command_signal
        $processDrained = $Records.process.drained; $outputComplete = $Records.process.output_complete
    }
    $stepRecords.Add([ordered]@{ name=$Name; evidence_root=$RelativeRoot; wrapper_exit=$Exit; slot_id=$Records.slot_id; token=$Records.token;
        owner_sha256=$Records.owner_sha256;
        process_sha256=(Get-Hash (Join-Path $Records.root 'process.json') 262144);
        finish_sha256=(Get-Hash (Join-Path $Records.root 'finish.json') 65536);
        finalization_sha256=(Get-Hash (Join-Path $Records.root 'finalization-input.json') 65536);
        process_payload_kind=$payloadKind; process_started=$Records.process_started;
        startup_error_kind=$Records.startup_error_kind; observation_sha256=$Records.observation_sha256; raw_candidate_present=$Records.raw_candidate_present;
        process_command_exit=$processExit; process_command_signal=$processSignal; process_drained=$processDrained; process_output_complete=$outputComplete;
        command_exit=$Records.finish.command_exit; termination_reason=$termination;
        owned_tail_terminated=$tailTerminated; drained=$Records.finalization.drained; finalization_drained=$Records.finalization.drained;
        evidence_exported=$Records.finalization.evidence_exported; lease_released=$Records.finish.lease_released })
}

function Assert-Source {
    $sha = @(& git -C $checkoutRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sha.Count -ne 1 -or $sha[0] -cne $ExpectedSourceSha) { throw 'OBSERVER_SOURCE_SHA_MISMATCH' }
    & git -C $checkoutRoot diff --quiet HEAD -- @sourceRoots
    if ($LASTEXITCODE -ne 0) { throw 'OBSERVER_DIRTY_SOURCE_INPUTS' }
    # A tracked Rust module can refer to an untracked input. Inspect only Git's
    # path inventory for the fixed source roots and never print/read that input.
    $untracked = @(& git -C $checkoutRoot ls-files --others --exclude-standard -- @sourceRoots)
    if ($LASTEXITCODE -ne 0 -or $untracked.Count -ne 0) { throw 'OBSERVER_UNTRACKED_SOURCE_INPUTS' }
}

function Revalidate-Source {
    Assert-Source
    foreach ($input in $inputRecords) {
        $path = Assert-Physical (Join-Path $checkoutRoot $input.path) $false
        if ([System.IO.FileInfo]::new($path).Length -ne $input.bytes -or (Get-Hash $path 1048576) -cne $input.sha256) { throw 'OBSERVER_SOURCE_INPUT_CHANGED' }
    }
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'OBSERVER_POWERSHELL_7_REQUIRED' }
    $actualTarget = if ($IsWindows -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'windows-x64' }
        elseif ($IsLinux -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'linux-x64' }
        elseif ($IsMacOS -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64') { 'macos-arm64' }
        else { throw 'OBSERVER_HOST_UNSUPPORTED' }
    if ($actualTarget -cne $Target) { throw 'OBSERVER_HOST_TARGET_MISMATCH' }
    $hostPrefix = @{ 'windows-x64'='windows-x86_64'; 'linux-x64'='linux-x86_64'; 'macos-arm64'='macos-aarch64' }[$Target]
    $expectedRustTarget = @{ 'windows-x64'='x86_64-pc-windows-msvc'; 'linux-x64'='x86_64-unknown-linux-gnu'; 'macos-arm64'='aarch64-apple-darwin' }[$Target]
    $checkoutRoot = Assert-Physical $Checkout $true
    $candidateEvidence = Assert-Physical $EvidenceRoot $true
    if (Is-Inside $candidateEvidence $checkoutRoot) { throw 'OBSERVER_EVIDENCE_BOUNDARY' }

    if ($Action -ceq 'header') {
        # All compiler setup and descendants run inside the outer JVM-purpose
        # owner. Never dump environment values or install another toolchain.
        $phase = 'compiler_selection'
        $headerSlot = Assert-Physical $ManagedSlotRoot $true
        $headerCatalog = Assert-Physical ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($headerSlot))) $true
        if ([System.IO.Path]::GetFileName($headerCatalog) -cne 'managed-v1' -or
            (Is-Inside $candidateEvidence $headerCatalog) -or (Is-Inside $headerCatalog $candidateEvidence)) { throw 'OBSERVER_HEADER_EVIDENCE_BOUNDARY' }
        $evidence = $candidateEvidence
        $compilerSelection = [ordered]@{ schema='mmmm-observer-compiler-selection/1'; source_sha=$ExpectedSourceSha; target=$Target;
            mode= $(if ($PSBoundParameters.ContainsKey('WindowsVsRoot')) { 'explicit_root' } elseif ($IsWindows) { 'installed_vswhere' } else { 'native_compiler' });
            selected_root_checked=$false; discovery_record_sha256=$null; launcher=$null; compiler=$null;
            whole_toolchain_image_verified=$false }
        $phase = 'compiler_jdk_root'
        $selectedJdk = Assert-Physical $JdkRoot $true
        if ($IsWindows) {
            if ($PSBoundParameters.ContainsKey('WindowsVsRoot')) {
                $phase = 'compiler_explicit_vs_root'
                # An empty or rejected explicit root never triggers discovery.
                $vs = Assert-Physical $WindowsVsRoot $true
            } else {
                $phase = 'compiler_installed_vs_discovery'
                $vs = Find-InstalledVisualStudio
                $compilerSelection.discovery_record_sha256 = Get-Hash (Join-Path $evidence 'observer-vswhere-discovery.json') 65536
            }
            $compilerSelection.selected_root_checked = $true
            $phase = 'compiler_devshell_launcher'
            $launcher = Assert-Physical (Join-Path $vs 'Common7/Tools/Launch-VsDevShell.ps1') $false
            $compilerSelection.launcher = [ordered]@{ role='selected_vs_devshell_launcher'; bytes=[System.IO.FileInfo]::new($launcher).Length; sha256=(Get-Hash $launcher 1048576) }
            $phase = 'compiler_devshell_setup'
            & $launcher -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
            $phase = 'compiler_command_lookup'
            $compilerCommand = Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        } else {
            $phase = 'compiler_command_lookup'
            $compilerName = if ($IsMacOS) { 'clang' } else { 'gcc' }
            $compilerCommand = Get-Command $compilerName -CommandType Application -ErrorAction Stop | Select-Object -First 1
        }
        $phase = 'compiler_physical_executable'
        $compilerItem = Get-Item -LiteralPath $compilerCommand.Source -Force
        $compilerTarget = $compilerItem.ResolveLinkTarget($true)
        $compiler = Assert-Physical $(if ($null -eq $compilerTarget) { $compilerItem.FullName } else { $compilerTarget.FullName }) $false
        $phase = 'compiler_executable_profile'
        if ($IsWindows -and (-not (Is-Inside $compiler $vs) -or $compiler -notmatch '[\\/]VC[\\/]Tools[\\/]MSVC[\\/][0-9.]+[\\/]bin[\\/]Hostx64[\\/]x64[\\/]cl\.exe$')) { throw 'OBSERVER_COMPILER_PROFILE_MISMATCH' }
        $compilerSelection.compiler = [ordered]@{ role='selected_physical_c_compiler'; bytes=[System.IO.FileInfo]::new($compiler).Length; sha256=(Get-Hash $compiler 536870912) }
        $phase = 'compiler_selection_export'
        Write-NewJson (Join-Path $evidence 'observer-compiler-selection.json') $compilerSelection 65536
        $phase = 'header_witness'
        # Use its own -File process: the ABI helper's exit belongs to that
        # process, while this launcher and all descendants retain the same
        # outer Rust-managed JVM-purpose owner and deadline.
        $headerPwsh = Assert-Physical ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) $false
        & $headerPwsh -NoProfile -File (Join-Path $checkoutRoot 'tools/bootstrap/observer-abi-witness.ps1') -Checkout $checkoutRoot -ManagedSlotRoot $headerSlot -JdkRoot $selectedJdk -CompilerPath $compiler -EvidenceRoot $evidence -ExpectedSourceSha $ExpectedSourceSha -Target $Target
        $headerHelperExit = $LASTEXITCODE
        if ($headerHelperExit -ne 0) { throw 'OBSERVER_HEADER_HELPER_FAILED' }
        $result.status = 'passed'
        exit 0
    }

    if ($RustTarget -cne $expectedRustTarget) { throw 'OBSERVER_RUST_TARGET_MISMATCH' }
    $output = Assert-Physical $OutputRoot $true
    $priorEvidence = Assert-Physical $JvmEvidenceRoot $true
    $xtaskProgram = Assert-Physical $Xtask $false
    $cargoProgram = Assert-Physical $Cargo $false
    $pwsh = Assert-Physical ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) $false
    $slotsRoot = Assert-Physical (Join-Path $output 'build/managed-v1/slots') $true
    $catalogRoot = Assert-Physical ([System.IO.Path]::GetDirectoryName($slotsRoot)) $true
    if ((Is-Inside $output $checkoutRoot) -or (Is-Inside $candidateEvidence $catalogRoot) -or (Is-Inside $catalogRoot $candidateEvidence) -or
        -not (Is-Inside $candidateEvidence $output) -or
        -not (Is-Inside $priorEvidence $output) -or -not (Is-Inside $xtaskProgram $slotsRoot)) { throw 'OBSERVER_OUTPUT_BOUNDARY' }
    $evidence = $candidateEvidence
    # Match storage.rs::path_identity for the already physical checkout. A
    # short-name/canonical spelling mismatch fails closed before any slot use.
    $checkoutIdentity = $checkoutRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if ($IsWindows) { $checkoutIdentity = $checkoutIdentity.Replace('/','\').TrimEnd('\').ToLowerInvariant() }
    $checkoutDigest = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($utf8.GetBytes($checkoutIdentity))).ToLowerInvariant()
    $hostOS = @{ 'windows-x64'='windows'; 'linux-x64'='linux'; 'macos-arm64'='macos' }[$Target]
    $hostArch = if ($Target -ceq 'macos-arm64') { 'aarch64' } else { 'x86_64' }
    $catalog = Read-Json (Join-Path ([System.IO.Path]::GetDirectoryName($slotsRoot)) 'catalog.json') 8192
    if ($catalog.schema -cne 'mmmm-managed-build/1' -or $catalog.catalog_id -cnotmatch '^[0-9a-f]{64}$') { throw 'OBSERVER_CATALOG_IDENTITY_INVALID' }

    $sourceRoots = @('Cargo.toml','Cargo.lock','rust-toolchain.toml','crates/mmmm-game-observer','crates/mmmm-native-process','tools/mmmm-xtask',
        'jvm/build.gradle','jvm/settings.gradle','jvm/definition-observer', 'tools/bootstrap/observer-ci.ps1',
        'tools/bootstrap/observer-abi-witness.c','tools/bootstrap/observer-abi-witness.ps1',
        'tools/bootstrap/jvm-ci.ps1','tools/bootstrap/jvm-runtime-probe.ps1','tools/bootstrap/jvm-archive.py',
        'tools/bootstrap/WindowsBootstrap.cs','.github/workflows/jvm.yml')
    $phase = 'source_inputs'
    Assert-Source
    $inputs = @(& git -C $checkoutRoot ls-files -- @sourceRoots)
    if ($LASTEXITCODE -ne 0 -or $inputs.Count -lt 20 -or $inputs.Count -gt 384) { throw 'OBSERVER_SOURCE_INVENTORY_BUDGET' }
    foreach ($required in @('Cargo.toml','Cargo.lock','rust-toolchain.toml','crates/mmmm-native-process/Cargo.toml',
            'crates/mmmm-native-process/src/lib.rs','crates/mmmm-native-process/src/darwin.rs','crates/mmmm-game-observer/build.rs',
            'crates/mmmm-game-observer/Cargo.toml','crates/mmmm-game-observer/src/lib.rs','crates/mmmm-game-observer/src/ffi.rs',
            'tools/bootstrap/observer-ci.ps1','tools/bootstrap/observer-abi-witness.c','tools/bootstrap/observer-abi-witness.ps1',
            '.github/workflows/jvm.yml')) {
        if ($required -cnotin $inputs) { throw 'OBSERVER_REQUIRED_SOURCE_NOT_TRACKED' }
    }
    $inputRecords = [System.Collections.Generic.List[object]]::new()
    $totalSourceBytes = 0L
    foreach ($relative in ($inputs | Sort-Object -CaseSensitive)) {
        if ($relative -cnotmatch '^[A-Za-z0-9_./$-]+$' -or $relative.Contains('..') -or
            $relative -match '(?i)(^|/)(\.env(?:\.[^/]*)?|.*credential[^/]*|.*service[_-]account[^/]*|id_rsa[^/]*|id_ed25519[^/]*|node_modules|dist|dist-server|build|coverage|models|checkpoints|\.cache)(/|$)' -or
            $relative -match '(?i)\.(pem|key|p12|pfx)$') { throw 'OBSERVER_DISALLOWED_SOURCE_PATH' }
        $path = Assert-Physical (Join-Path $checkoutRoot $relative) $false
        if (-not (Is-Inside $path $checkoutRoot)) { throw 'OBSERVER_SOURCE_INPUT_ESCAPE' }
        $bytes = [System.IO.FileInfo]::new($path).Length
        $totalSourceBytes += $bytes
        if ($totalSourceBytes -gt 16777216) { throw 'OBSERVER_SOURCE_AGGREGATE_BUDGET' }
        $inputRecords.Add([ordered]@{ path=$relative; bytes=$bytes; sha256=(Get-Hash $path 1048576) })
    }
    $selectedInputs = New-Directory (Join-Path $evidence 'selected-inputs')
    $sourceManifest = Join-Path $selectedInputs 'build-source-manifest.json'
    Write-NewJson $sourceManifest ([ordered]@{ schema='mmmm-observer-build-inputs/1'; source_sha=$ExpectedSourceSha;
        rust_toolchain='1.96.0'; rust_target=$RustTarget; scope='development_fixture'; inputs=$inputRecords.ToArray();
        input_inventory_complete_for_selected_roots=$true; whole_toolchain_image_verified=$false; source_admission_granted=$false })
    $result.source_manifest_sha256 = Get-Hash $sourceManifest 1048576

    $phase = 'prior_jvm_evidence'
    $jvmResult = Read-Json (Join-Path $priorEvidence 'verification/jvm-result.json') 1048576
    $toolchains = Read-Json (Join-Path $priorEvidence 'verification/jvm-toolchains.json')
    $priorManaged = Get-ManagedRecords (Join-Path $priorEvidence 'managed') 'jvm'
    Assert-ManagedSuccess $priorManaged $true
    if ($jvmResult.schema -cne 'mmmm-jvm-ci-result/1' -or $jvmResult.source_sha -cne $ExpectedSourceSha -or $jvmResult.target -cne $Target -or
        $jvmResult.status -cne 'passed' -or $jvmResult.gradle_exit -ne 0 -or @($jvmResult.required_tasks).Count -ne 11 -or
        @($jvmResult.tasks).Count -ne 11 -or @($jvmResult.tasks | Where-Object status -CNE 'executed').Count -ne 0 -or
        @($jvmResult.tests).Count -ne 7 -or @($jvmResult.tests | Where-Object passed -NE $true).Count -ne 0 -or
        $toolchains.schema -cne 'mmmm-jvm-toolchains/1' -or $toolchains.target -cne $Target) { throw 'OBSERVER_PRIOR_JVM_SUCCESS_REQUIRED' }
    $result.jvm_verification = 'passed_prior_record'
    $result.prior_jvm_record = [ordered]@{ slot_id=$priorManaged.slot_id; token=$priorManaged.token; owner_sha256=$priorManaged.owner_sha256;
        process_sha256=(Get-Hash (Join-Path $priorManaged.root 'process.json') 262144);
        finish_sha256=(Get-Hash (Join-Path $priorManaged.root 'finish.json') 65536);
        finalization_sha256=(Get-Hash (Join-Path $priorManaged.root 'finalization-input.json') 65536);
        jvm_result_sha256=(Get-Hash (Join-Path $priorEvidence 'verification/jvm-result.json') 1048576);
        toolchains_sha256=(Get-Hash (Join-Path $priorEvidence 'verification/jvm-toolchains.json') 65536) }
    $jvmSlot = Assert-Physical (Join-Path $slotsRoot $priorManaged.slot_id) $true
    $gradleBuild = Assert-Physical (Join-Path $jvmSlot 'cache/gradle-build') $true
    $toolchainRoot = Assert-Physical (Join-Path $gradleBuild 'ci-toolchains') $true
    $jdkProfiles = @{
        'windows-x64' = @{ file='OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip'; sha='00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283'; suffix=''; java='bin/java.exe'; library='mmmm_game_observer.dll'; libraries=@('bin/server/jvm.dll','bin/java.dll','bin/jimage.dll','bin/zip.dll','bin/verify.dll','bin/instrument.dll') }
        'linux-x64' = @{ file='OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz'; sha='dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e'; suffix=''; java='bin/java'; library='libmmmm_game_observer.so'; libraries=@('lib/server/libjvm.so','lib/libjava.so','lib/libjimage.so','lib/libzip.so','lib/libverify.so','lib/libinstrument.so') }
        'macos-arm64' = @{ file='OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4.1_1.tar.gz'; sha='61979887f7506a24a57439ff99adb8b3a7fc89977d9cfe3b8984f58a981b7b9d'; suffix='/Contents/Home'; java='bin/java'; library='libmmmm_game_observer.dylib'; libraries=@('lib/server/libjvm.dylib','lib/libjava.dylib','lib/libjimage.dylib','lib/libzip.dylib','lib/libverify.dylib','lib/libinstrument.dylib') }
    }
    $jdkProfile = $jdkProfiles[$Target]
    $jdkRecords = @($toolchains.toolchains | Where-Object name -CEQ 'temurin')
    if ($jdkRecords.Count -ne 1 -or $jdkRecords[0].archive -cne $jdkProfile.file -or $jdkRecords[0].sha256 -cne $jdkProfile.sha -or
        $jdkRecords[0].extraction.schema -cne 'mmmm-jvm-extraction/1' -or $jdkRecords[0].extraction.archive_sha256 -cne $jdkProfile.sha) { throw 'OBSERVER_SELECTED_JDK_RECORD_MISMATCH' }
    $archive = Assert-Physical (Join-Path $toolchainRoot $jdkProfile.file) $false
    if ((Get-Hash $archive 201326592) -cne $jdkProfile.sha) { throw 'OBSERVER_SELECTED_JDK_ARCHIVE_MISMATCH' }
    $jdk = Assert-Physical (Join-Path $toolchainRoot "temurin/jdk-25.0.4.1+1$($jdkProfile.suffix)") $true
    $java = Assert-Physical (Join-Path $jdk $jdkProfile.java) $false
    $modules = Assert-Physical (Join-Path $jdk 'lib/modules') $false
    $jar = Assert-Physical (Join-Path $gradleBuild 'definition-observer/libs/definition-observer-0.1.0.jar') $false
    $jarSha = Get-Hash $jar 16777216

    $phase = 'native_build'
    $result.native_build = 'running'
    $buildEvidence = New-Directory (Join-Path $evidence 'native-build')
    & $xtaskProgram run --checkout $checkoutRoot --output-root $output --evidence-root $buildEvidence --purpose checks --timeout-seconds 1200 --owned-tail-policy terminate-build -- $cargoProgram build -p mmmm-game-observer --target $RustTarget --locked | Out-Null
    $buildExit = $LASTEXITCODE
    $buildRecords = Get-ManagedRecords $buildEvidence 'checks'
    Add-ManagedStep 'native_build' 'native-build' $buildExit $buildRecords
    if ($buildExit -ne 0) { throw 'OBSERVER_NATIVE_BUILD_FAILED' }
    Assert-ManagedSuccess $buildRecords $true
    Revalidate-Source
    $nativeOutput = Assert-Physical (Join-Path $slotsRoot "$($buildRecords.slot_id)/cache/cargo-target/$RustTarget/debug/$($jdkProfile.library)") $false
    $nativeSha = Get-Hash $nativeOutput 67108864
    # Cargo may hard-link its top-level output. Create exactly one new owned
    # copy, compare bytes, then let the native startup pin enforce nlink == 1.
    $nativeCopy = Join-Path $selectedInputs $jdkProfile.library
    $sourceStream = [System.IO.File]::Open($nativeOutput, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $copyStream = $null
    try {
        $copyStream = [System.IO.File]::Open($nativeCopy, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $expectedBytes = $sourceStream.Length
        if ($expectedBytes -le 0 -or $expectedBytes -gt 67108864) { throw 'OBSERVER_NATIVE_COPY_BUDGET' }
        $buffer = [byte[]]::new(65536); $copiedBytes = 0L
        while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $copiedBytes += $read
            if ($copiedBytes -gt $expectedBytes -or $copiedBytes -gt 67108864) { throw 'OBSERVER_NATIVE_COPY_BUDGET' }
            $copyStream.Write($buffer, 0, $read)
        }
        if ($copiedBytes -ne $expectedBytes) { throw 'OBSERVER_NATIVE_COPY_LENGTH_CHANGED' }
        $copyStream.Flush($true)
    } finally { if ($null -ne $copyStream) { $copyStream.Dispose() }; $sourceStream.Dispose() }
    $nativeCopy = Assert-Physical $nativeCopy $false
    if ((Get-Hash $nativeCopy 67108864) -cne $nativeSha -or (Get-Hash $nativeOutput 67108864) -cne $nativeSha) { throw 'OBSERVER_NATIVE_COPY_MISMATCH' }
    $result.input_pins = @([ordered]@{ role='observer_library'; bytes=[System.IO.FileInfo]::new($nativeCopy).Length; sha256=$nativeSha },
        [ordered]@{ role='observer_jar'; bytes=[System.IO.FileInfo]::new($jar).Length; sha256=$jarSha },
        [ordered]@{ role='jdk_archive'; bytes=[System.IO.FileInfo]::new($archive).Length; sha256=$jdkProfile.sha })
    $result.native_build = 'passed'

    $phase = 'header_witness'
    $result.header_witness = 'running'
    $headerEvidence = New-Directory (Join-Path $evidence 'header-witness')
    $headerManaged = New-Directory (Join-Path $evidence 'header-managed')
    $headerArgs = @('run','--checkout',$checkoutRoot,'--output-root',$output,'--evidence-root',$headerManaged,'--purpose','jvm','--timeout-seconds','180','--owned-tail-policy','terminate-build','--',
        $pwsh,'-NoProfile','-File',(Join-Path $checkoutRoot 'tools/bootstrap/observer-ci.ps1'),'-Action','header','-Checkout',$checkoutRoot,'-EvidenceRoot',$headerEvidence,
        '-ExpectedSourceSha',$ExpectedSourceSha,'-Target',$Target,'-ManagedSlotRoot',$jvmSlot,'-JdkRoot',$jdk)
    if ($PSBoundParameters.ContainsKey('WindowsVsRoot')) { $headerArgs += @('-WindowsVsRoot',$WindowsVsRoot) }
    & $xtaskProgram @headerArgs | Out-Null
    $headerExit = $LASTEXITCODE
    $headerRecords = Get-ManagedRecords $headerManaged 'jvm'
    Add-ManagedStep 'header_witness' 'header-managed' $headerExit $headerRecords
    if ($headerExit -ne 0) { throw 'OBSERVER_HEADER_WITNESS_FAILED' }
    Assert-ManagedSuccess $headerRecords $true
    $headerResult = Read-Json (Join-Path $headerEvidence 'observer-abi-result.json')
    if ($headerResult.schema -cne 'mmmm-observer-abi-result/1' -or $headerResult.source_sha -cne $ExpectedSourceSha -or $headerResult.target -cne $Target -or
        $headerResult.status -cne 'passed' -or @($headerResult.input_pins).Count -ne 8 -or @($headerResult.input_pins | Where-Object revalidated -NE $true).Count -ne 0) { throw 'OBSERVER_HEADER_RESULT_INVALID' }
    $result.header_witness = 'passed'
    Revalidate-Source

    $phase = 'definition_startup'
    $result.definition_startup = 'running'
    $startupEvidence = New-Directory (Join-Path $evidence 'definition-startup')
    $startupArgs = @('definition-startup','--checkout',$checkoutRoot,'--output-root',$output,'--evidence-root',$startupEvidence,
        '--java-executable',$java,'--observer-library',$nativeCopy,'--observer-jar',$jar,'--jdk-archive',$archive,
        '--jdk-modules',$modules,'--build-source-manifest',$sourceManifest)
    $index = 1
    foreach ($relativeLibrary in $jdkProfile.libraries) {
        $libraryPath = Assert-Physical (Join-Path $jdk $relativeLibrary) $false
        $startupArgs += @("--jdk-library-$index",$libraryPath); $index++
    }
    & $xtaskProgram @startupArgs | Out-Null
    $startupExit = $LASTEXITCODE
    $startupRecords = Get-ManagedRecords $startupEvidence 'definition-startup'
    Add-ManagedStep 'definition_startup' 'definition-startup' $startupExit $startupRecords
    if ($startupExit -ne 0) { $result.definition_startup = 'failed'; throw 'OBSERVER_DEFINITION_STARTUP_FAILED' }
    Assert-ManagedSuccess $startupRecords
    $observation = $startupRecords.observation
    if ($observation.schema -cne 'mmmm-definition-startup-observation/1' -or $observation.scope -cne 'development_fixture' -or
        $observation.status -cne 'observed' -or $observation.process_started -ne $true -or $observation.raw_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'OBSERVER_DEFINITION_OBSERVATION_INVALID' }
    if ((Get-Hash (Join-Path $startupRecords.root 'definition-startup.abi2.bin') 18874368) -cne $observation.raw_sha256 -or
        (Get-Hash $nativeCopy 67108864) -cne $nativeSha -or (Get-Hash $jar 16777216) -cne $jarSha -or
        (Get-Hash $sourceManifest 1048576) -cne $result.source_manifest_sha256) { throw 'OBSERVER_FINAL_SELECTED_INPUT_CHANGED' }
    Revalidate-Source
    $result.definition_startup = 'observed'
    $result.status = 'passed'; $phase = 'complete'
} catch {
    $result.status = 'failed'; $result.failure = Failure-Shape $_.Exception
    if ($phase -ceq 'definition_startup') { $result.definition_startup = 'failed' }
    if ($Action -ceq 'header') {
        # Setup failure precedes the ABI helper's own result. Preserve it as a
        # separate factual record instead of manufacturing a header witness.
        if ($null -ne $evidence) {
            try { Write-NewJson (Join-Path $evidence 'observer-header-launcher-failure.json') ([ordered]@{
                schema='mmmm-observer-header-launcher-failure/1'; source_sha=$ExpectedSourceSha; target=$Target;
                failure=$result.failure; compiler_selection=$(if (Get-Variable compilerSelection -ErrorAction SilentlyContinue) { $compilerSelection } else { $null });
                abi_witness='not_established'; native_supervision='external_record_required' }) 65536 } catch { }
        }
    }
} finally {
    if ($Action -ceq 'verify' -and $null -ne $evidence) {
        $result.phase = $phase; $result.steps = $stepRecords.ToArray()
        try { Write-NewJson (Join-Path $evidence 'observer-result.json') $result }
        catch { $result.status = 'failed'; [Console]::Error.WriteLine('MMMM_OBSERVER_RESULT_EXPORT_FAILED') }
    }
}
if ($result.status -cne 'passed') { [Console]::Error.WriteLine('MMMM_OBSERVER_CI_FAILED'); exit 1 }
exit 0
