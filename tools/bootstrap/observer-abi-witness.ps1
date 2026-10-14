# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MMMM contributors
# Invoke as a dedicated pwsh -NoProfile -File command inside mmmm-xtask run.
# The caller must bind its actual managed process/finalization record to this
# header witness. This helper neither acquires a lease nor grants VM policy.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Checkout,
    [Parameter(Mandatory)][string]$ManagedSlotRoot,
    [Parameter(Mandatory)][string]$JdkRoot,
    [Parameter(Mandatory)][string]$CompilerPath,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceSha,
    [Parameter(Mandatory)][ValidateSet('windows-x64','linux-x64','macos-arm64')][string]$Target
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$comparison = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$totalLimit = 120000L
$evidence = $null
$phase = 'preflight'
$exitCode = 1
$pins = [System.Collections.Generic.List[object]]::new()
$steps = [System.Collections.Generic.List[object]]::new()
$result = [ordered]@{
    schema='mmmm-observer-abi-result/1'; source_sha=$ExpectedSourceSha; target=$Target;
    source_sha_verification='caller_bound_not_verified_by_helper';
    status='not_run'; phase=$phase; input_pins=@(); steps=@(); witness=$null; failure=$null;
    limits=[ordered]@{ total_ms=$totalLimit; compile_ms=90000; witness_ms=10000; drain_reserve_ms=3000;
        step_output_bytes=1048576; witness_stdout_bytes=4096; compiler_input_bytes=536870912 };
    managed_supervision='external_record_required'; vm_startup='not_run'; game_verification='not_run';
    target_policy_granted=$false; whole_toolchain_image_verified=$false; pin_disposal_failures=@();
    total_deadline_exceeded=$false
}

function Assert-Time {
    if ($clock.ElapsedMilliseconds -ge $totalLimit) { throw 'ABI_WITNESS_TOTAL_DEADLINE' }
}

function Assert-Physical([string]$Path, [bool]$Directory) {
    Assert-Time
    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) { throw 'ABI_ABSOLUTE_PATH_REQUIRED' }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.Equals([System.IO.Path]::GetPathRoot($full), $comparison)) { throw 'ABI_NONROOT_PATH_REQUIRED' }
    if ($IsWindows -and ($full.StartsWith('\\') -or $full -notmatch '^[A-Za-z]:\\')) { throw 'ABI_LOCAL_DOS_PATH_REQUIRED' }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'ABI_PHYSICAL_PATH_REQUIRED'
    }
    $cursor = if ($Directory) { $full } else { [System.IO.Path]::GetDirectoryName($full) }
    while ($cursor) {
        $ancestor = Get-Item -LiteralPath $cursor -Force
        if (-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'ABI_PHYSICAL_ANCESTRY_REQUIRED'
        }
        $next = [System.IO.Path]::GetDirectoryName($cursor)
        if ($next -eq $cursor) { break }
        $cursor = $next
    }
    return $full.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
}

function Is-Inside([string]$Path, [string]$Root) {
    return $Path.Equals($Root, $comparison) -or
        $Path.StartsWith($Root.TrimEnd('/','\') + [System.IO.Path]::DirectorySeparatorChar, $comparison)
}

function Hash-Stream([System.IO.Stream]$Stream, [long]$Limit) {
    if ($Stream.Length -le 0 -or $Stream.Length -gt $Limit) { throw 'ABI_INPUT_SIZE_INVALID' }
    $Stream.Position = 0
    $digest = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while (($count = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            Assert-Time
            $total += $count
            if ($total -gt $Limit) { throw 'ABI_INPUT_SIZE_INVALID' }
            $digest.AppendData($buffer, 0, $count)
        }
        if ($total -ne $Stream.Length) { throw 'ABI_INPUT_LENGTH_CHANGED' }
        return [System.Convert]::ToHexString($digest.GetHashAndReset()).ToLowerInvariant()
    } finally { $digest.Dispose() }
}

function Pin-Input([string]$Role, [string]$Path, [long]$Limit) {
    $full = Assert-Physical $Path $false
    $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $pin = [pscustomobject]@{ role=$Role; path=$full; limit=$Limit; stream=$stream;
            bytes=$stream.Length; sha256=(Hash-Stream $stream $Limit); revalidated=$false }
        $pins.Add($pin)
        return $pin
    } catch { $stream.Dispose(); throw }
}

function Revalidate-Pins {
    foreach ($pin in $pins) {
        $physical = Assert-Physical $pin.path $false
        if (-not $physical.Equals($pin.path, $comparison) -or $pin.stream.Length -ne $pin.bytes -or
            (Hash-Stream $pin.stream $pin.limit) -cne $pin.sha256) { throw 'ABI_HELD_INPUT_CHANGED' }
        $current = [System.IO.File]::Open($physical, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            if ($current.Length -ne $pin.bytes -or (Hash-Stream $current $pin.limit) -cne $pin.sha256) {
                throw 'ABI_SELECTED_INPUT_CHANGED'
            }
        } finally { $current.Dispose() }
        $pin.revalidated = $true
    }
}

function Write-NewJson([string]$Path, $Value) {
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 16 -Compress))
    if ($bytes.Length -gt 65536) { throw 'ABI_RESULT_SIZE_INVALID' }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Failure-Shape([System.Exception]$Exception) {
    $chain = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $null -ne $Exception -and $index -lt 6; $index++) {
        $type = $Exception.GetType().FullName
        if ($type -cnotmatch '^[A-Za-z0-9_.+`]{1,192}$') { $type = 'withheld' }
        $code = if ($Exception.Message -cmatch '^ABI_[A-Z0-9_]{1,96}$') { $Exception.Message } else { $null }
        $nativeCode = if ($Exception -is [System.ComponentModel.Win32Exception]) { $Exception.NativeErrorCode } else { $null }
        $chain.Add([ordered]@{ type=$type; hresult=$Exception.HResult; native_code=$nativeCode; static_code=$code })
        $Exception = $Exception.InnerException
    }
    return [ordered]@{ phase=$phase; exceptions=$chain.ToArray(); chain_truncated=($null -ne $Exception) }
}

function Invoke-BoundedStep([string]$Name, [string]$Program, [string[]]$Arguments,
        [string[]]$ArgumentTemplate, [int]$BudgetMs, [int]$StdoutLimit = 1048576) {
    Assert-Time
    $start = $clock.ElapsedMilliseconds
    $deadline = [Math]::Min($totalLimit, $start + $BudgetMs)
    $workDeadline = $deadline - 3000
    if ($workDeadline -le $start) { throw 'ABI_STEP_DEADLINE_UNAVAILABLE' }
    $stdout = $null
    $stderr = $null
    $process = [System.Diagnostics.Process]::new()
    $cancel = [System.Threading.CancellationTokenSource]::new()
    $outcome = [ordered]@{ name=$Name; argv_template=$ArgumentTemplate; argv_sha256=$null;
        command_exit=$null; root_exited=$false; pipes_complete=$false; output_complete=$false;
        stdout_bytes=0L; stderr_bytes=0L; stdout_sha256=$null; stderr_sha256=$null; elapsed_ms=0L;
        termination_attempted=$false; termination_failure=$null; stop_reason=$null; failure=$null; finalization_failures=@();
        descendant_drain='external_record_required' }
    $finalization = [System.Collections.Generic.List[object]]::new()
    $nativeText = $null
    $started = $false
    try {
        $stdout = [System.IO.File]::Open((Join-Path $evidence "$Name.stdout.bin"), [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $stderr = [System.IO.File]::Open((Join-Path $evidence "$Name.stderr.bin"), [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $argumentBytes = $utf8.GetBytes((ConvertTo-Json -InputObject @($Arguments) -Compress))
        $outcome.argv_sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($argumentBytes)).ToLowerInvariant()
        $info = [System.Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $Program; $info.WorkingDirectory = $work
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true; $info.RedirectStandardInput = $true
        foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
        # Remove only fixed injection names without reading or recording values.
        foreach ($injectionName in @('CL','_CL_','CFLAGS','CPPFLAGS','LDFLAGS','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH',
                'OBJC_INCLUDE_PATH','GCC_EXEC_PREFIX','COMPILER_PATH','LIBRARY_PATH','GCC_COMPARE_DEBUG',
                'COLLECT_GCC_OPTIONS','DEPENDENCIES_OUTPUT','SUNPRO_DEPENDENCIES','CCC_OVERRIDE_OPTIONS')) {
            $null = $info.Environment.Remove($injectionName)
        }
        foreach ($temporaryName in @('TMP','TEMP','TMPDIR')) { $info.Environment[$temporaryName] = $work }
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'ABI_PROCESS_START_FAILED' }
        $started = $true
        $process.StandardInput.Close()
        $pumps = @(
            [pscustomobject]@{ source=$process.StandardOutput.BaseStream; output=$stdout; buffer=[byte[]]::new(8192); task=$null; done=$false; count=0L; limit=$StdoutLimit },
            [pscustomobject]@{ source=$process.StandardError.BaseStream; output=$stderr; buffer=[byte[]]::new(8192); task=$null; done=$false; count=0L; limit=1048576 }
        )
        foreach ($pump in $pumps) { $pump.task = $pump.source.ReadAsync($pump.buffer, 0, $pump.buffer.Length, $cancel.Token) }
        while ($true) {
            foreach ($pump in $pumps) {
                if (-not $pump.done -and $pump.task.IsCompleted) {
                    $count = $pump.task.GetAwaiter().GetResult()
                    if ($count -eq 0) { $pump.done = $true; continue }
                    if ($pump.count + $count -gt $pump.limit -or $pumps[0].count + $pumps[1].count + $count -gt 1048576) {
                        $outcome.stop_reason = 'output_limit'
                    } else {
                        $pump.output.Write($pump.buffer, 0, $count)
                        $pump.count += $count
                        $pump.task = $pump.source.ReadAsync($pump.buffer, 0, $pump.buffer.Length, $cancel.Token)
                    }
                }
            }
            $outcome.root_exited = $process.HasExited
            $outcome.pipes_complete = $pumps[0].done -and $pumps[1].done
            if ($clock.ElapsedMilliseconds -ge $workDeadline -and $null -eq $outcome.stop_reason) { $outcome.stop_reason = 'deadline' }
            if ($outcome.root_exited -and $outcome.pipes_complete) { break }
            if ($null -ne $outcome.stop_reason -and -not $outcome.termination_attempted) {
                $outcome.termination_attempted = $true
                if (-not $outcome.root_exited) { $process.Kill($true) }
            }
            if ($clock.ElapsedMilliseconds -ge $deadline -or $outcome.stop_reason -eq 'output_limit') { break }
            [System.Threading.Thread]::Sleep(10)
        }
        if ($process.HasExited) { $outcome.command_exit = $process.ExitCode; $outcome.root_exited = $true }
        $outcome.stdout_bytes = $pumps[0].count; $outcome.stderr_bytes = $pumps[1].count
        $outcome.output_complete = $outcome.pipes_complete -and $null -eq $outcome.stop_reason
        if ($Name -eq 'witness' -and $outcome.output_complete -and $outcome.stdout_bytes -le 4096) {
            $stdout.Position = 0
            $bytes = [byte[]]::new([int]$stdout.Length)
            $read = $stdout.Read($bytes, 0, $bytes.Length)
            if ($read -ne $bytes.Length) { throw 'ABI_CAPTURE_LENGTH_CHANGED' }
            $nativeText = $utf8.GetString($bytes)
        }
    } catch {
        $outcome.failure = Failure-Shape $_.Exception
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    $outcome.termination_attempted = $true
                    $process.Kill($true)
                }
            } catch { $outcome.stop_reason = 'termination_unconfirmed'; $outcome.termination_failure = Failure-Shape $_.Exception }
        }
    } finally {
        try { $cancel.Cancel() }
        catch { $finalization.Add([ordered]@{ operation='cancel_reads'; failure=(Failure-Shape $_.Exception) }) }
        if ($started) {
            try {
                if ($process.HasExited) { $outcome.command_exit = $process.ExitCode; $outcome.root_exited = $true }
            } catch { $finalization.Add([ordered]@{ operation='observe_exit'; failure=(Failure-Shape $_.Exception) }) }
        }
        # Preserve the original outcome even if log flush/hash/disposal fails.
        # Captured byte counts come from the actual held files, including a
        # prefix retained before a read/write error; incomplete output stays false.
        foreach ($entry in @(@($stdout, 'stdout'), @($stderr, 'stderr'))) {
            if ($null -eq $entry[0]) {
                $outcome[$entry[1] + '_bytes'] = $null
                continue
            }
            try { $entry[0].Flush($true) }
            catch { $finalization.Add([ordered]@{ operation=($entry[1] + '_flush'); failure=(Failure-Shape $_.Exception) }) }
            try {
                $outcome[$entry[1] + '_bytes'] = $entry[0].Length
            } catch {
                $outcome[$entry[1] + '_bytes'] = $null
                $finalization.Add([ordered]@{ operation=($entry[1] + '_length'); failure=(Failure-Shape $_.Exception) })
            }
            try {
                $entry[0].Position = 0
                $outcome[$entry[1] + '_sha256'] = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($entry[0])).ToLowerInvariant()
            } catch {
                $finalization.Add([ordered]@{ operation=($entry[1] + '_hash'); failure=(Failure-Shape $_.Exception) })
            }
            try { $entry[0].Dispose() }
            catch { $finalization.Add([ordered]@{ operation=($entry[1] + '_dispose'); failure=(Failure-Shape $_.Exception) }) }
        }
        try { $process.Dispose() }
        catch { $finalization.Add([ordered]@{ operation='process_dispose'; failure=(Failure-Shape $_.Exception) }) }
        try { $cancel.Dispose() }
        catch { $finalization.Add([ordered]@{ operation='cancel_dispose'; failure=(Failure-Shape $_.Exception) }) }
        $outcome.finalization_failures = $finalization.ToArray()
        if ($finalization.Count) { $outcome.output_complete = $false }
        $outcome.elapsed_ms = $clock.ElapsedMilliseconds - $start
        $steps.Add($outcome)
    }
    if ($outcome.command_exit -ne 0 -or -not $outcome.root_exited -or -not $outcome.output_complete -or
        $null -ne $outcome.failure -or $null -ne $outcome.stop_reason) { throw 'ABI_NATIVE_STEP_FAILED' }
    return $nativeText
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'ABI_POWERSHELL_7_REQUIRED' }
    $actual = if ($IsWindows -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'windows-x64' }
        elseif ($IsLinux -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'linux-x64' }
        elseif ($IsMacOS -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64') { 'macos-arm64' }
        else { throw 'ABI_HOST_UNSUPPORTED' }
    if ($actual -cne $Target) { throw 'ABI_HOST_TARGET_MISMATCH' }
    $checkoutRoot = Assert-Physical $Checkout $true
    $slot = Assert-Physical $ManagedSlotRoot $true
    $slotName = [System.IO.Path]::GetFileName($slot)
    $hostPrefix = @{ 'windows-x64'='windows-x86_64'; 'linux-x64'='linux-x86_64'; 'macos-arm64'='macos-aarch64' }[$Target]
    if ($slotName -cnotmatch ('^' + [regex]::Escape($hostPrefix) + '-(?<checkout>[0-9a-f]{24})-(checks|jvm|observer-abi-witness)$')) {
        throw 'ABI_MANAGED_SLOT_REQUIRED'
    }
    $checkoutKey = $Matches['checkout']
    $slots = Assert-Physical ([System.IO.Path]::GetDirectoryName($slot)) $true
    $buildCatalog = Assert-Physical ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($slots))) $true
    if ([System.IO.Path]::GetFileName($slots) -cne 'slots' -or
        [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($slots)) -cne 'managed-v1' -or
        [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($slots))) -cne 'build') {
        throw 'ABI_MANAGED_CATALOG_REQUIRED'
    }
    $scratch = Assert-Physical (Join-Path $slot 'scratch') $true
    $candidateEvidence = Assert-Physical $EvidenceRoot $true
    if ((Is-Inside $slot $checkoutRoot) -or (Is-Inside $candidateEvidence $checkoutRoot) -or (Is-Inside $candidateEvidence $buildCatalog) -or
        (Is-Inside $checkoutRoot $slot)) { throw 'ABI_OUTPUT_BOUNDARY_INVALID' }
    $evidence = $candidateEvidence
    $expectedHelper = Assert-Physical (Join-Path $checkoutRoot 'tools/bootstrap/observer-abi-witness.ps1') $false
    $actualHelper = Assert-Physical $PSCommandPath $false
    if (-not $actualHelper.Equals($expectedHelper, $comparison)) { throw 'ABI_EXECUTED_HELPER_PATH_MISMATCH' }
    $jvmSlot = Join-Path $slots "$hostPrefix-$checkoutKey-jvm"
    $macHome = if ($Target -eq 'macos-arm64') { '/Contents/Home' } else { '' }
    $jdkCandidates = @(
        (Join-Path $jvmSlot "cache/gradle-build/toolchains/temurin-25.0.4.1-1-$Target/jdk-25.0.4.1+1$macHome"),
        (Join-Path $jvmSlot "cache/gradle-build/ci-toolchains/temurin/jdk-25.0.4.1+1$macHome")
    )
    $jdk = Assert-Physical $JdkRoot $true
    if (-not @($jdkCandidates | Where-Object { [System.IO.Path]::GetFullPath($_).Equals($jdk, $comparison) }).Count) {
        throw 'ABI_SELECTED_JDK_PATH_INVALID'
    }
    $compiler = Assert-Physical $CompilerPath $false
    $compilerName = [System.IO.Path]::GetFileName($compiler)
    $compilerPattern = if ($Target -eq 'windows-x64') { '^cl\.exe$' }
        elseif ($Target -eq 'linux-x64') { '^(cc|gcc(-[0-9]+)?|x86_64-linux-gnu-gcc(-[0-9]+)?|clang(-[0-9]+)?)$' }
        else { '^clang(-[0-9]+)?$' }
    if ($compilerName -cnotmatch $compilerPattern) { throw 'ABI_COMPILER_KIND_INVALID' }
    $workPath = Join-Path $scratch 'observer-abi-witness'
    if (Test-Path -LiteralPath $workPath) { throw 'ABI_SCRATCH_ALREADY_EXISTS' }
    [System.IO.Directory]::CreateDirectory($workPath) | Out-Null
    $work = Assert-Physical $workPath $true
    $platformDirectory = @{ 'windows-x64'='win32'; 'linux-x64'='linux'; 'macos-arm64'='darwin' }[$Target]
    $profile = @{ 'windows-x64'='windows-x64-msvc'; 'linux-x64'='linux-x64-gnu'; 'macos-arm64'='macos-arm64-darwin' }[$Target]
    $macro = @{ 'windows-x64'='1'; 'linux-x64'='2'; 'macos-arm64'='3' }[$Target]
    $include = Assert-Physical (Join-Path $jdk 'include') $true
    $platformInclude = Assert-Physical (Join-Path $include $platformDirectory) $true
    $source = Pin-Input 'fixture_source' (Join-Path $checkoutRoot 'tools/bootstrap/observer-abi-witness.c') 262144
    $null = Pin-Input 'helper_source' $actualHelper 262144
    $null = Pin-Input 'rust_ffi_source' (Join-Path $checkoutRoot 'crates/mmmm-game-observer/src/ffi.rs') 262144
    $null = Pin-Input 'compiler_executable' $compiler 536870912
    $null = Pin-Input 'jdk_jni_header' (Join-Path $include 'jni.h') 1048576
    $null = Pin-Input 'jdk_jvmti_header' (Join-Path $include 'jvmti.h') 1048576
    $null = Pin-Input 'jdk_platform_header' (Join-Path $platformInclude 'jni_md.h') 1048576
    $program = Join-Path $work $(if ($IsWindows) { 'observer-abi-witness.exe' } else { 'observer-abi-witness' })
    $phase = 'compile'
    if ($Target -eq 'windows-x64') {
        $compileArgs = @('/nologo','/std:c17','/W4','/WX','/TC','/Bv',"/DMMMM_OBSERVER_ABI_PROFILE=$macro",
            "/I$include","/I$platformInclude","/Fo$(Join-Path $work 'observer-abi-witness.obj')", "/Fe$program",$source.path,
            '/link','/INCREMENTAL:NO','/MANIFEST:NO')
        $template = @('/nologo','/std:c17','/W4','/WX','/TC','/Bv','/DMMMM_OBSERVER_ABI_PROFILE=1',
            '/I<jdk_include>','/I<jdk_platform_include>','/Fo<owned_object>','/Fe<owned_executable>','<fixture_source>',
            '/link','/INCREMENTAL:NO','/MANIFEST:NO')
    } else {
        $compileArgs = @('-std=c11','-Wall','-Wextra','-Werror',"-DMMMM_OBSERVER_ABI_PROFILE=$macro",'-I',$include,'-I',$platformInclude)
        $template = @('-std=c11','-Wall','-Wextra','-Werror',"-DMMMM_OBSERVER_ABI_PROFILE=$macro",'-I','<jdk_include>','-I','<jdk_platform_include>')
        if ($compilerName -cmatch '^clang(-[0-9]+)?$') {
            $compileArgs += '--no-default-config'; $template += '--no-default-config'
        }
        if ($Target -eq 'macos-arm64') { $compileArgs += @('-arch','arm64'); $template += @('-arch','arm64') }
        else { $compileArgs += '-m64'; $template += '-m64' }
        $compileArgs += @($source.path,'-o',$program)
        $template += @('<fixture_source>','-o','<owned_executable>')
    }
    $null = Invoke-BoundedStep 'compiler' $compiler $compileArgs $template 90000
    $binary = Pin-Input 'witness_executable' $program 16777216
    $phase = 'witness'
    $raw = Invoke-BoundedStep -Name 'witness' -Program $binary.path -Arguments @() -ArgumentTemplate @() -BudgetMs 10000 -StdoutLimit 4096
    if ($steps[1].stderr_bytes -ne 0 -or [string]::IsNullOrEmpty($raw) -or $raw -cnotmatch '^\{[^\r\n]+\}\r?\n$') {
        throw 'ABI_WITNESS_FRAME_INVALID'
    }
    # This is the owned fixture's exact frame, not a general evidence-import API.
    # Exact bytes reject duplicate/unknown keys, coercible scalar types and a
    # partial report before any selected-header result can be called passed.
    $expectedWitness = [ordered]@{
        schema='mmmm-observer-c-abi-witness/1'; profile=$profile; status='passed';
        pointer_bytes=8; pointer_alignment=8; endianness='little';
        primitive_bytes=[ordered]@{ jint=4; jsize=4; jlong=8; jboolean=1; jbyte=1; jchar=2 };
        jvmti_enum_bytes=4; jvmti_enum_alignment=4; capabilities_bytes=16; capabilities_alignment=4;
        capability_ordinals=@(3,26,30,35,37,42); capability_words_hex=@('44000008','00000428','00000000','00000000');
        individual_capability_checks=6; combined_capability_checks=1; callbacks_bytes=312; callbacks_alignment=8;
        callback_slots=@(0,1,4,5,6,17); native_method_bytes=24; native_method_alignment=8; native_method_offsets=@(0,8,16);
        jni_slots=@(6,21,22,23,24,33,36,164,169,170,171,176,200,208,215,220,228);
        jvmti_positions=@(2,18,47,48,49,52,57,64,65,66,75,88,89,122,133,140,142,146);
        java_vm_get_env_slot=6; table_signature_checks=36; callback_signature_checks=6; entry_signature_checks=4;
        set_event_variadic=$true; vm_invoked=$false; table_entries_called=$false; target_policy_granted=$false
    }
    $expectedFrame = ConvertTo-Json -InputObject $expectedWitness -Depth 8 -Compress
    if (-not $raw.TrimEnd([char[]]@("`r","`n")).Equals($expectedFrame, [System.StringComparison]::Ordinal)) {
        throw 'ABI_WITNESS_RESULT_INVALID'
    }
    $witness = ConvertFrom-Json -InputObject $raw -AsHashtable -NoEnumerate
    $phase = 'revalidate'
    Revalidate-Pins
    Assert-Time
    $result.witness = $witness
    $result.status = 'passed'; $exitCode = 0
} catch {
    $result.status = 'failed'
    $result.failure = Failure-Shape $_.Exception
} finally {
    $result.phase = $phase
    $result.steps = $steps.ToArray()
    $result.input_pins = @($pins | ForEach-Object { [ordered]@{ role=$_.role; bytes=$_.bytes; sha256=$_.sha256; revalidated=$_.revalidated } })
    $disposalFailures = [System.Collections.Generic.List[object]]::new()
    foreach ($pin in $pins) {
        try { $pin.stream.Dispose() }
        catch { $disposalFailures.Add([ordered]@{ role=$pin.role; failure=(Failure-Shape $_.Exception) }) }
    }
    $result.pin_disposal_failures = $disposalFailures.ToArray()
    if ($disposalFailures.Count) { $result.status = 'failed'; $exitCode = 1 }
    if ($clock.ElapsedMilliseconds -ge $totalLimit) {
        $result.total_deadline_exceeded = $true; $result.status = 'failed'; $exitCode = 1
    }
    $result.elapsed_ms = $clock.ElapsedMilliseconds
    if ($null -ne $evidence) {
        try { Write-NewJson (Join-Path $evidence 'observer-abi-result.json') $result }
        catch {
            $exitCode = 1
            [Console]::Error.WriteLine('MMMM_OBSERVER_ABI_RESULT_EXPORT_FAILED')
            [Console]::Error.WriteLine((ConvertTo-Json -InputObject (Failure-Shape $_.Exception) -Depth 10 -Compress))
        }
    }
    # Keep the pre-export snapshot; the managed record must require this exit.
    if ($clock.ElapsedMilliseconds -ge $totalLimit) {
        $exitCode = 1
        [Console]::Error.WriteLine('MMMM_OBSERVER_ABI_TOTAL_DEADLINE_EXCEEDED')
    }
    if ($exitCode -ne 0) { [Console]::Error.WriteLine('MMMM_OBSERVER_ABI_WITNESS_FAILED') }
}
exit $exitCode
