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
    # actions/runner-images Windows2025-Readme, image 20261004.281.1, lists
    # this VS root. Actual path/compiler admission is still required per run.
    [string]$WindowsVsRoot = 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
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
    return [pscustomobject]@{ root=$recordRoot; slot_id=$slotEntries[0].Name; token=$tokens[0].Name; owner_sha256=(Get-Hash $ownerPath 8192);
        finish=$finish; process=$process; finalization=$finalization }
}

function Assert-ManagedSuccess($Records, [bool]$AllowBuildTail = $false) {
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
    $stepRecords.Add([ordered]@{ name=$Name; evidence_root=$RelativeRoot; wrapper_exit=$Exit; slot_id=$Records.slot_id; token=$Records.token;
        owner_sha256=$Records.owner_sha256;
        process_sha256=(Get-Hash (Join-Path $Records.root 'process.json') 262144);
        finish_sha256=(Get-Hash (Join-Path $Records.root 'finish.json') 65536);
        finalization_sha256=(Get-Hash (Join-Path $Records.root 'finalization-input.json') 65536);
        command_exit=$Records.finish.command_exit; termination_reason=$Records.process.termination_reason;
        owned_tail_terminated=$Records.process.owned_tail_terminated; drained=$Records.finalization.drained;
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
        $selectedJdk = Assert-Physical $JdkRoot $true
        if ($IsWindows) {
            $vs = Assert-Physical $WindowsVsRoot $true
            $launcher = Assert-Physical (Join-Path $vs 'Common7/Tools/Launch-VsDevShell.ps1') $false
            & $launcher -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
            $compilerCommand = Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        } else {
            $compilerName = if ($IsMacOS) { 'clang' } else { 'gcc' }
            $compilerCommand = Get-Command $compilerName -CommandType Application -ErrorAction Stop | Select-Object -First 1
        }
        $compilerItem = Get-Item -LiteralPath $compilerCommand.Source -Force
        $compilerTarget = $compilerItem.ResolveLinkTarget($true)
        $compiler = Assert-Physical $(if ($null -eq $compilerTarget) { $compilerItem.FullName } else { $compilerTarget.FullName }) $false
        if ($IsWindows -and (-not (Is-Inside $compiler $vs) -or $compiler -notmatch '[\\/]VC[\\/]Tools[\\/]MSVC[\\/][0-9.]+[\\/]bin[\\/]Hostx64[\\/]x64[\\/]cl\.exe$')) { throw 'OBSERVER_COMPILER_PROFILE_MISMATCH' }
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
    & $xtaskProgram run --checkout $checkoutRoot --output-root $output --evidence-root $headerManaged --purpose jvm --timeout-seconds 180 --owned-tail-policy terminate-build -- $pwsh -NoProfile -File (Join-Path $checkoutRoot 'tools/bootstrap/observer-ci.ps1') -Action header -Checkout $checkoutRoot -EvidenceRoot $headerEvidence -ExpectedSourceSha $ExpectedSourceSha -Target $Target -ManagedSlotRoot $jvmSlot -JdkRoot $jdk -WindowsVsRoot $WindowsVsRoot | Out-Null
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
    if ($startupExit -ne 0) { throw 'OBSERVER_DEFINITION_STARTUP_FAILED' }
    Assert-ManagedSuccess $startupRecords
    $observation = Read-Json (Join-Path $startupRecords.root 'definition-startup.json') 262144
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
    if ($Action -ceq 'header') {
        # Setup failure precedes the ABI helper's own result. Preserve it as a
        # separate factual record instead of manufacturing a header witness.
        if ($null -ne $evidence) {
            try { Write-NewJson (Join-Path $evidence 'observer-header-launcher-failure.json') ([ordered]@{
                schema='mmmm-observer-header-launcher-failure/1'; source_sha=$ExpectedSourceSha; target=$Target;
                failure=$result.failure; abi_witness='not_established'; native_supervision='external_record_required' }) 65536 } catch { }
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
