# JVM build infrastructure only. Invoke inside mmmm-xtask run --purpose jvm.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Checkout,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceSha,
    [Parameter(Mandatory)][ValidateSet('windows-x64','linux-x64','macos-arm64')][string]$Target,
    [Parameter(Mandatory)][string]$Python,
    [ValidatePattern('(?-i)^[0-9a-f]{40}$')][string]$ToolchainGeneration,
    [switch]$DevelopmentJars
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$pathComparison = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
$phase = 'preflight'
$operation = 'managed_paths'
$developmentClock = if ($DevelopmentJars) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
$testModules = @('provider-sdk', 'host-core', 'public-java-adapter', 'fabric-host',
    'definition-observer', 'fixture-legacy', 'fixture-provider')
$tasks = @(':provider-sdk:test', ':host-core:test', ':public-java-adapter:test', ':fabric-host:compileJava', ':fabric-host:test',
    ':definition-observer:test', ':definition-observer:jar', ':fixture-legacy:test', ':fixture-legacy:jar',
    ':fixture-provider:test', ':fixture-provider:jar')
$nativeExit = $null
$record = [ordered]@{ schema='mmmm-jvm-ci-result/1'; source_sha=$ExpectedSourceSha; target=$Target;
    status='not_run'; phase=$phase; gradle_exit=$null; required_tasks=$tasks; required_test_modules=$testModules; tasks=@(); tests=@();
    game_verification='not_run'; release_verification='not_run'; evidence_errors=@(); failure_details=@();
    profile=[ordered]@{ gradle='9.6.0'; jdk_archive_release='25.0.4.1+1'; gradle_workers=2;
        junit_forks=1; launcher_heap_bytes=1073741824; daemon_heap_bytes=1073741824; test_heap_bytes=536870912;
        launcher_metaspace_bytes=402653184; daemon_metaspace_bytes=402653184; fixed_jvm_argument_count=19;
        managed_output_bytes=67108864; timeout_seconds=1200; slot_bytes=8589934592; catalog_bytes=12884901888;
        shared_build_cache=$false; configuration_cache=$false; parallel_projects=$false; automatic_jdk_download=$false;
        successful_evidence_reuse=$false; kernel_memory_quota='not_established' } }

function Assert-PhysicalPath([string]$Path, [bool]$Directory) {
    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) { throw 'ABSOLUTE_PATH_REQUIRED' }
    $full = [System.IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'PHYSICAL_PATH_REQUIRED'
    }
    $ancestor = if ($Directory) { $full } else { [System.IO.Path]::GetDirectoryName($full) }
    while ($ancestor) {
        $parent = Get-Item -LiteralPath $ancestor -Force
        if (-not $parent.PSIsContainer -or ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'PHYSICAL_ANCESTRY_REQUIRED' }
        $next = [System.IO.Path]::GetDirectoryName($ancestor)
        if ($next -eq $ancestor) { break }
        $ancestor = $next
    }
    return $full
}

function Get-NativePath([string]$Path, [bool]$Directory) {
    $physical = Assert-PhysicalPath $Path $Directory
    if (-not $IsWindows) { return $physical }
    $parent = if ($Directory) { $physical } else { [System.IO.Path]::GetDirectoryName($physical) }
    $identity = [Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($parent)
    $dos = if ($physical.StartsWith('\\?\', [System.StringComparison]::Ordinal)) { $physical.Substring(4) } else { $physical }
    if ($dos -cnotmatch '^[A-Za-z]:\\' -or $dos.Length -ge 248 -or $dos.StartsWith('\\')) { throw 'NATIVE_LOCAL_DOS_PATH_REQUIRED' }
    $dosParent = if ($Directory) { $dos } else { [System.IO.Path]::GetDirectoryName($dos) }
    if (-not $identity.Equals([Mmmm.Bootstrap.WindowsBoundary]::PhysicalDirectory($dosParent), $pathComparison)) { throw 'NATIVE_DIRECTORY_IDENTITY_CHANGED' }
    return $dos
}

function Is-Inside([string]$Path, [string]$Root) {
    return $Path.Equals($Root, $pathComparison) -or $Path.StartsWith($Root.TrimEnd('/','\') + [System.IO.Path]::DirectorySeparatorChar, $pathComparison)
}

function New-PhysicalDirectory([string]$Path) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    return Assert-PhysicalPath $Path $true
}

function New-ToolchainOutput([string]$Base, [string]$JdkArchive, [bool]$UseGeneration, [string]$Generation) {
    $baseRoot = New-PhysicalDirectory $Base
    $selected = if ($UseGeneration) { Join-Path $baseRoot $Generation } else { $baseRoot }
    if ($UseGeneration -and (Test-Path -LiteralPath $selected)) { throw 'JVM_TOOLCHAIN_GENERATION_ALREADY_EXISTS' }
    # Inspect only immediate names and metadata in this fixed owned directory.
    # Flat output counts as one generation; never delete or reuse an old one.
    $flat = $false; $generations = 0; $entries = 0
    foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($baseRoot)) {
        $entries++
        if ($entries -gt 6) { throw 'JVM_TOOLCHAIN_GENERATION_ENTRY_BUDGET' }
        $child = Get-Item -LiteralPath $childPath -Force
        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'JVM_TOOLCHAIN_GENERATION_PHYSICAL_REQUIRED' }
        if ($child.PSIsContainer) {
            if ($child.Name -cmatch '^[0-9a-f]{40}$') { $generations++ }
            elseif ($child.Name -cin @('temurin','gradle')) { $flat = $true }
            else { throw 'JVM_TOOLCHAIN_GENERATION_LAYOUT_INVALID' }
        } elseif ($child.Name -cin @($JdkArchive,'gradle-9.6.0-bin.zip')) { $flat = $true }
        else { throw 'JVM_TOOLCHAIN_GENERATION_LAYOUT_INVALID' }
    }
    if (-not $UseGeneration -and $flat) { throw 'JVM_TOOLCHAIN_FLAT_OUTPUT_ALREADY_EXISTS' }
    if ($generations + [int]$flat -ge 2) { throw 'JVM_TOOLCHAIN_GENERATION_LIMIT' }
    if ($UseGeneration) { return New-PhysicalDirectory $selected }
    return $baseRoot
}

function Write-NewJson([string]$Path, $Value, [int]$Limit = 65536) {
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 12 -Compress))
    if ($bytes.Length -gt $Limit) { throw 'EVIDENCE_RECORD_BUDGET_EXCEEDED' }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Get-SafeFailureRecord([System.Management.Automation.ErrorRecord]$Failure, [string]$Operation) {
    # Exception messages, targets and stack traces can include private paths or
    # request values. Preserve the original typed chain and bounded safe fields.
    $chain = [System.Collections.Generic.List[object]]::new()
    $exception = $Failure.Exception
    for ($index = 0; $null -ne $exception -and $index -lt 8; $index++) {
        $type = $exception.GetType().FullName
        if ($type.Length -gt 192 -or $type -cnotmatch '^[A-Za-z0-9_.+`]+$') { $type = 'withheld' }
        $code = if ($exception.Message.Length -le 128 -and $exception.Message -cmatch '^[A-Z][A-Z0-9_]+$') { $exception.Message } else { $null }
        $chain.Add([ordered]@{ type=$type; hresult=$exception.HResult; static_code=$code })
        $exception = $exception.InnerException
    }
    $errorId = $Failure.FullyQualifiedErrorId
    if ($errorId.Length -gt 256 -or $errorId -cnotmatch '^[A-Za-z0-9_.,+-]+$') { $errorId = 'withheld' }
    $sourceLine = 0
    $source = 'unavailable'
    if ($null -ne $Failure.InvocationInfo -and ([string]$Failure.InvocationInfo.ScriptName).Equals($PSCommandPath, $pathComparison)) {
        $source = 'tools/bootstrap/jvm-ci.ps1'
        $sourceLine = $Failure.InvocationInfo.ScriptLineNumber
    }
    return [ordered]@{ phase=$phase; operation=$Operation; category=$Failure.CategoryInfo.Category.ToString();
        error_id=$errorId; source=$source; source_line=$sourceLine; exceptions=$chain.ToArray(); chain_truncated=($null -ne $exception) }
}

function Get-RegularHash([string]$Path, [long]$Limit) {
    $full = Assert-PhysicalPath $Path $false
    $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $Limit) { throw 'FILE_BUDGET_EXCEEDED' }
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    } finally { $stream.Dispose() }
}

function Get-GradleAgentPin([string]$Path) {
    $full = Get-NativePath $Path $false
    $before = [System.IO.FileInfo]::new($full)
    $length = $before.Length; $modified = $before.LastWriteTimeUtc.Ticks; $created = $before.CreationTimeUtc.Ticks
    if ($length -le 0 -or $length -gt 10MB) { throw 'GRADLE_AGENT_FILE_BUDGET' }
    $stream = $null; $hash = $null; $failure = $null; $pin = $null
    try {
        $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -ne $length) { throw 'GRADLE_AGENT_SIZE_CHANGED' }
        $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer = [byte[]]::new(65536); $observed = 0L
        while ($true) {
            $count = $stream.Read($buffer, 0, [int][System.Math]::Min($buffer.Length, $length - $observed + 1))
            if ($count -eq 0) { break }
            $observed += $count
            if ($observed -gt $length) { throw 'GRADLE_AGENT_SIZE_CHANGED' }
            $hash.AppendData($buffer, 0, $count)
        }
        if ($observed -ne $length -or $stream.Length -ne $length) { throw 'GRADLE_AGENT_SIZE_CHANGED' }
        $after = [System.IO.FileInfo]::new((Get-NativePath $full $false))
        if ($after.Length -ne $length -or $after.LastWriteTimeUtc.Ticks -ne $modified -or $after.CreationTimeUtc.Ticks -ne $created) { throw 'GRADLE_AGENT_METADATA_CHANGED' }
        $pin = [ordered]@{ bytes=$length; sha256=[System.Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant(); modified=$modified; created=$created }
    } catch { $failure = $_ }
    foreach ($resource in @(@{ value=$hash; stage='gradle_agent_hash_close' }, @{ value=$stream; stage='gradle_agent_stream_close' })) {
        if ($null -eq $resource.value) { continue }
        try { $resource.value.Dispose() }
        catch {
            $record.failure_details += Get-SafeFailureRecord $_ $resource.stage
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) { throw $failure }
    return $pin
}

function Get-PinnedArchive([string]$Url, [string]$Path, [string]$Digest) {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $deadline = [System.Threading.CancellationTokenSource]::new([System.TimeSpan]::FromSeconds(300))
    $response = $null
    try {
        $uri = [System.Uri]$Url
        for ($redirect = 0; $redirect -le 6; $redirect++) {
            if ($uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.DnsSafeHost -cnotin @(
                'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com',
                'services.gradle.org','downloads.gradle.org'
            )) { throw 'UNTRUSTED_ARCHIVE_DOWNLOAD_OR_REDIRECT' }
            $response = $client.GetAsync($uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
            if ([int]$response.StatusCode -in @(301,302,303,307,308)) {
                if ($redirect -eq 6 -or $null -eq $response.Headers.Location) { throw 'ARCHIVE_REDIRECT_BUDGET_EXCEEDED' }
                $next = $response.Headers.Location
                $uri = if ($next.IsAbsoluteUri) { $next } else { [System.Uri]::new($uri, $next) }
                $response.Dispose(); $response = $null
                continue
            }
            if (-not $response.IsSuccessStatusCode) { throw 'ARCHIVE_HTTP_FAILED' }
            if ($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt 512MB) { throw 'ARCHIVE_DOWNLOAD_BUDGET_EXCEEDED' }
            $source = $response.Content.ReadAsStreamAsync($deadline.Token).GetAwaiter().GetResult()
            $output = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $buffer = [byte[]]::new(65536)
                $total = 0L
                while (($count = $source.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -ne 0) {
                    $total += $count
                    if ($total -gt 512MB) { throw 'ARCHIVE_DOWNLOAD_BUDGET_EXCEEDED' }
                    $output.Write($buffer, 0, $count)
                }
                if ($total -le 0 -or ($null -ne $response.Content.Headers.ContentLength -and $total -ne $response.Content.Headers.ContentLength)) { throw 'ARCHIVE_DOWNLOAD_LENGTH_MISMATCH' }
                $output.Flush($true)
            } finally { $output.Dispose(); $source.Dispose() }
            if ((Get-RegularHash $Path 512MB) -cne $Digest) { throw 'ARCHIVE_DIGEST_MISMATCH' }
            return $total
        }
        throw 'ARCHIVE_REDIRECT_BUDGET_EXCEEDED'
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        $deadline.Dispose(); $client.Dispose(); $handler.Dispose()
    }
}

function Export-TestSummary([string]$Module, [string]$ResultRoot) {
    $root = Assert-PhysicalPath $ResultRoot $true
    $files = @(Get-ChildItem -LiteralPath $root -File -Filter 'TEST-*.xml' -Force)
    if ($files.Count -lt 1 -or $files.Count -gt 256) { throw 'TEST_REPORT_COUNT_INVALID' }
    $summaries = [System.Collections.Generic.List[object]]::new()
    $totalBytes = 0L; $totalTests = 0L; $totalFailures = 0L; $totalErrors = 0L; $totalSkipped = 0L
    foreach ($file in ($files | Sort-Object Name)) {
        $full = Assert-PhysicalPath $file.FullName $false
        if ($file.Name -cnotmatch '^TEST-[A-Za-z0-9_.$-]+\.xml$' -or $file.Length -gt 4MB) { throw 'TEST_REPORT_BUDGET_OR_NAME_INVALID' }
        $totalBytes += $file.Length
        if ($totalBytes -gt 16MB) { throw 'TEST_REPORT_AGGREGATE_BUDGET_EXCEEDED' }
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 4MB
        $reader = [System.Xml.XmlReader]::Create($full, $settings)
        try { $document = [System.Xml.XmlDocument]::new(); $document.XmlResolver = $null; $document.Load($reader) } finally { $reader.Dispose() }
        # PowerShell's XML adapter maps the Gradle testsuite @name attribute
        # onto .Name. Read the actual XML element, with no namespace accepted.
        $rootElement = $document.PSBase.DocumentElement
        if ($null -eq $rootElement -or $rootElement.PSBase.Name -cne 'testsuite' -or
            $rootElement.PSBase.LocalName -cne 'testsuite' -or $rootElement.PSBase.NamespaceURI -cne '') { throw 'TEST_REPORT_ROOT_INVALID' }
        $counts = @{}
        foreach ($key in @('tests','failures','errors','skipped')) {
            $value = $rootElement.PSBase.GetAttribute($key)
            $parsed = 0L
            if ($value -cnotmatch '^[0-9]+$' -or -not [long]::TryParse($value, [ref]$parsed) -or $parsed -gt 100000) { throw 'TEST_REPORT_COUNTS_INVALID' }
            $counts[$key] = $parsed
        }
        $cases = @($document.SelectNodes('/testsuite/testcase'))
        if ($cases.Count -ne $counts.tests -or @($document.SelectNodes('/testsuite/testcase/failure')).Count -ne $counts.failures -or
            @($document.SelectNodes('/testsuite/testcase/error')).Count -ne $counts.errors -or @($document.SelectNodes('/testsuite/testcase/skipped')).Count -ne $counts.skipped) { throw 'TEST_REPORT_COUNTS_MISMATCH' }
        $summaries.Add([ordered]@{ file=$file.Name; sha256=(Get-RegularHash $full 4MB); bytes=$file.Length;
            tests=$counts.tests; failures=$counts.failures; errors=$counts.errors; skipped=$counts.skipped })
        $totalTests += $counts.tests; $totalFailures += $counts.failures; $totalErrors += $counts.errors; $totalSkipped += $counts.skipped
    }
    $summary = [ordered]@{ module=$Module; source_sha=$ExpectedSourceSha; reports=$summaries.ToArray();
        tests=$totalTests; failures=$totalFailures; errors=$totalErrors; skipped=$totalSkipped;
        passed=($totalTests -gt $totalSkipped -and $totalFailures -eq 0 -and $totalErrors -eq 0) }
    Write-NewJson (Join-Path $evidence "$Module-tests.json") $summary
    return $summary
}

# Development packaging consumes the completed verification in this same owned
# invocation. None of these helpers writes the original verification record.
function Assert-DevelopmentTime {
    if ($null -eq $developmentClock -or $developmentClock.Elapsed.TotalSeconds -ge 1200) { throw 'DEVELOPMENT_JARS_DEADLINE' }
}

function Get-DevelopmentPin([string]$Path, [long]$Limit, $Failures, [switch]$AllowEmpty) {
    Assert-DevelopmentTime
    $full = Get-NativePath $Path $false
    $before = [System.IO.FileInfo]::new($full)
    $length = $before.Length; $modified = $before.LastWriteTimeUtc.Ticks; $created = $before.CreationTimeUtc.Ticks
    if ($length -lt 0 -or (-not $AllowEmpty -and $length -eq 0) -or $length -gt $Limit) { throw 'DEVELOPMENT_FILE_BUDGET' }
    $stream = $null; $hash = $null; $failure = $null; $pin = $null
    try {
        $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -ne $length) { throw 'DEVELOPMENT_FILE_SIZE_CHANGED' }
        $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer = [byte[]]::new(65536); $observed = 0L
        while ($true) {
            Assert-DevelopmentTime
            $count = $stream.Read($buffer, 0, [int][System.Math]::Min($buffer.Length, $length - $observed + 1))
            if ($count -eq 0) { break }
            $observed += $count
            if ($observed -gt $length) { throw 'DEVELOPMENT_FILE_SIZE_CHANGED' }
            $hash.AppendData($buffer, 0, $count)
        }
        $after = [System.IO.FileInfo]::new((Get-NativePath $full $false))
        if ($observed -ne $length -or $stream.Length -ne $length -or $after.Length -ne $length -or
            $after.LastWriteTimeUtc.Ticks -ne $modified -or $after.CreationTimeUtc.Ticks -ne $created) { throw 'DEVELOPMENT_FILE_CHANGED' }
        $pin = [ordered]@{ bytes=$length; sha256=[System.Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant(); modified=$modified; created=$created }
    } catch { $failure = $_ }
    foreach ($resource in @(@{value=$hash; stage='development_hash_close'}, @{value=$stream; stage='development_stream_close'})) {
        if ($null -eq $resource.value) { continue }
        try { $resource.value.Dispose() } catch {
            $Failures.Add((Get-SafeFailureRecord $_ $resource.stage))
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) { throw $failure }
    return $pin
}

function Assert-DevelopmentPin($Expected, $Actual) {
    foreach ($field in @('bytes','sha256','modified','created')) {
        if ($Expected[$field] -cne $Actual[$field]) { throw 'DEVELOPMENT_SELECTED_INPUT_CHANGED' }
    }
}

function Read-DevelopmentBytes([string]$Path, [int]$Limit, $Failures) {
    $full = Get-NativePath $Path $false
    $stream = $null; $failure = $null; $answer = $null
    try {
        $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $length = $stream.Length
        if ($length -lt 0 -or $length -gt $Limit) { throw 'DEVELOPMENT_METADATA_BUDGET' }
        Get-NativePath $full $false | Out-Null
        if ($stream.Length -ne $length) { throw 'DEVELOPMENT_METADATA_CHANGED' }
        $answer = [byte[]]::new([int]$length); $observed = 0
        while ($observed -lt $answer.Length) {
            Assert-DevelopmentTime
            $count = $stream.Read($answer, $observed, $answer.Length-$observed)
            if ($count -le 0) { throw 'DEVELOPMENT_METADATA_CHANGED' }
            $observed += $count
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) { throw 'DEVELOPMENT_METADATA_CHANGED' }
    } catch { $failure = $_ }
    if ($null -ne $stream) {
        try { $stream.Dispose() } catch {
            $Failures.Add((Get-SafeFailureRecord $_ 'development_metadata_close'))
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) { throw $failure }
    return ,$answer
}

function Assert-DevelopmentSources($Inputs, $Failures) {
    Assert-DevelopmentTime
    $actual = @(& git -C $checkoutRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $actual.Count -ne 1 -or $actual[0] -cne $ExpectedSourceSha) { throw 'DEVELOPMENT_SOURCE_SHA_CHANGED' }
    & git -C $checkoutRoot diff --quiet HEAD -- jvm contracts examples tests/example-index.json tests/digest-fixtures.json tools/bootstrap/jvm-ci.ps1 tools/bootstrap/jvm-runtime-probe.ps1 tools/bootstrap/jvm-archive.py .github/workflows/jvm.yml tools/bootstrap/WindowsBootstrap.cs
    if ($LASTEXITCODE -ne 0) { throw 'DEVELOPMENT_SOURCE_CHANGED' }
    foreach ($input in $Inputs) {
        $pin = Get-DevelopmentPin (Join-Path $checkoutRoot $input.path) 10MB $Failures -AllowEmpty
        if ($pin.bytes -ne $input.bytes -or $pin.sha256 -cne $input.sha256) { throw 'DEVELOPMENT_SOURCE_INPUT_CHANGED' }
    }
}

function Copy-DevelopmentJar([string]$Source, [string]$Destination, $Artifact, $Failures) {
    $full = Get-NativePath $Source $false
    $before = [System.IO.FileInfo]::new($full)
    if ($before.Length -ne $Artifact.bytes -or $before.Length -le 0 -or $before.Length -gt 64MB) { throw 'DEVELOPMENT_JAR_BUDGET' }
    $length = $before.Length; $modified = $before.LastWriteTimeUtc.Ticks; $created = $before.CreationTimeUtc.Ticks
    $sourceStream = $null; $outputStream = $null; $hash = $null; $failure = $null; $observed = 0L
    try {
        $sourceStream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($sourceStream.Length -ne $length) { throw 'DEVELOPMENT_JAR_CHANGED' }
        $outputStream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer = [byte[]]::new(65536)
        while ($true) {
            Assert-DevelopmentTime
            $count = $sourceStream.Read($buffer, 0, [int][System.Math]::Min($buffer.Length, $length-$observed+1))
            if ($count -eq 0) { break }
            $observed += $count
            if ($observed -gt $length -or $observed -gt 64MB) { throw 'DEVELOPMENT_JAR_CHANGED' }
            $hash.AppendData($buffer, 0, $count); $outputStream.Write($buffer, 0, $count)
        }
        $after = [System.IO.FileInfo]::new((Get-NativePath $full $false))
        if ($observed -ne $length -or $sourceStream.Length -ne $length -or $after.Length -ne $length -or
            $after.LastWriteTimeUtc.Ticks -ne $modified -or $after.CreationTimeUtc.Ticks -ne $created -or
            [System.Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant() -cne $Artifact.sha256) { throw 'DEVELOPMENT_JAR_CHANGED' }
        $outputStream.Flush($true)
    } catch { $failure = $_ }
    foreach ($resource in @(@{value=$hash;stage='development_copy_hash_close'}, @{value=$outputStream;stage='development_copy_output_close'}, @{value=$sourceStream;stage='development_copy_input_close'})) {
        if ($null -eq $resource.value) { continue }
        try { $resource.value.Dispose() } catch {
            $Failures.Add((Get-SafeFailureRecord $_ $resource.stage))
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) { throw $failure }
    $copied = Get-DevelopmentPin $Destination 64MB $Failures
    if ($copied.bytes -ne $Artifact.bytes -or $copied.sha256 -cne $Artifact.sha256) { throw 'DEVELOPMENT_JAR_COPY_CHANGED' }
    return $copied
}

function Write-DevelopmentResult([string]$Root, $Value, $Failures) {
    $raw = $utf8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 12 -Compress))
    if ($raw.Length -gt 65536) { throw 'DEVELOPMENT_RESULT_BUDGET' }
    $pending = Join-Path $Root 'development-jars-result.pending.json'
    $stream = $null; $failure = $null
    try {
        $stream = [System.IO.File]::Open($pending, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Write($raw,0,$raw.Length); $stream.Flush($true)
    } catch { $failure = $_ }
    if ($null -ne $stream) {
        try { $stream.Dispose() } catch {
            $Failures.Add((Get-SafeFailureRecord $_ 'development_result_stream_close'))
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) { throw $failure }
    $pin = Get-DevelopmentPin $pending 65536 $Failures
    if ($pin.bytes -ne $raw.Length -or $pin.sha256 -cne [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()) { throw 'DEVELOPMENT_RESULT_CHANGED' }
    # Publish only the fully written, closed and verified record. Failure keeps
    # the pending evidence; no failed export publishes a provisional success.
    [System.IO.File]::Move($pending, (Join-Path $Root 'development-jars-result.json'))
}

function Invoke-DevelopmentJars {
    $savedPhase = $phase; $savedOperation = $operation
    $failures = [System.Collections.Generic.List[object]]::new()
    $package = [ordered]@{ schema='mmmm-jvm-development-jars-result/1'; scope='development'; source_sha=$ExpectedSourceSha;
        target=$Target; status='not_run'; phase='preflight'; gradle_exit=$null; source_post_checked=$false;
        selected_files_post_checked=$false; product_proof_issued=$false; source_admission_granted=$false;
        sdk_public_format_verified=$false; game_verification='not_run'; release_verification='not_run';
        artifacts=@(); failure_details=@(); whole_toolchain_image_verified=$false;
        physical_identity_mode=$null; directory_identity_mode=$null }
    $packageRoot = $null; $success = $false
    try {
        $phase = 'development_jars'; $operation = 'development_preflight'
        Assert-DevelopmentTime
        $packageRootPath = Join-Path $evidence 'development-jars'
        if (Test-Path -LiteralPath $packageRootPath) { throw 'DEVELOPMENT_OUTPUT_ALREADY_EXISTS' }
        $packageRoot = Get-NativePath (New-PhysicalDirectory $packageRootPath) $true
        if (-not (Is-Inside $packageRoot $evidence) -or (Is-Inside $packageRoot $slot) -or (Is-Inside $packageRoot $checkoutRoot)) { throw 'DEVELOPMENT_OUTPUT_BOUNDARY' }
        $verificationPin = Get-DevelopmentPin (Join-Path $evidence 'jvm-result.json') 1MB $failures
        $package.verification_result_sha256 = $verificationPin.sha256
        $package.source_inputs_sha256 = $record.source_inputs_sha256
        $package.toolchain_generation = $generation
        Assert-DevelopmentSources $inputRecords $failures
        $selected = [ordered]@{ java=$java; jdk_release=$releaseFile; jdk_modules=(Join-Path $javaHome 'lib/modules');
            gradle_main=$gradleMain; gradle_agent=$gradleAgent; helper=$PSCommandPath }
        $selected['jdk_vm'] = Join-Path $javaHome $(if ($IsWindows) { 'bin/server/jvm.dll' } elseif ($IsMacOS) { 'lib/server/libjvm.dylib' } else { 'lib/server/libjvm.so' })
        foreach ($profile in $profiles) { $selected['archive_'+$profile.name] = Join-Path $toolchains $profile.file }
        $pins = [ordered]@{}
        foreach ($name in $selected.Keys) { $pins[$name] = Get-DevelopmentPin $selected[$name] 512MB $failures }
        if ($pins.gradle_agent.sha256 -cne $agentPin.sha256 -or $pins.gradle_agent.bytes -ne $agentPin.bytes) { throw 'DEVELOPMENT_AGENT_BINDING_CHANGED' }
        if ($pins.jdk_release.sha256 -cne $record.jdk_release_sha256) { throw 'DEVELOPMENT_JDK_RELEASE_CHANGED' }
        foreach ($profile in $profiles) {
            if ($pins['archive_'+$profile.name].sha256 -cne $profile.sha) { throw 'DEVELOPMENT_ARCHIVE_PIN_CHANGED' }
        }
        $package.selected_files_before = $pins
        $packageInit = Join-Path $scratch 'jvm-development-jars.init.gradle'
        $packageInitText = @'
import groovy.json.JsonOutput
def output = new File(System.getProperty('mmmm.developmentJars.evidence'))
def sourceSha = System.getProperty('mmmm.ci.sourceSha')
def target = System.getProperty('mmmm.developmentJars.target')
def expectedNumeric = __MMMM_FIXED_NUMERIC_ARGS__
def actualArgs = java.lang.management.ManagementFactory.runtimeMXBean.inputArguments
if (actualArgs.size() > 64 || actualArgs.any { it.getBytes('UTF-8').length > 4096 } || actualArgs.sum { it.getBytes('UTF-8').length } > 16384) throw new GradleException('DEVELOPMENT_VM_ARGUMENT_BUDGET')
def numeric = actualArgs.findAll { it.startsWith('-Xms') || it.startsWith('-Xmx') || it.startsWith('-XX:MaxMetaspaceSize=') }
def facts = [schema:'mmmm-jvm-development-build-vm/1', source_sha:sourceSha, target:target,
    gradle_version:org.gradle.util.GradleVersion.current().version, max_heap_bytes:Runtime.runtime.maxMemory(),
    input_argument_count:actualArgs.size(), fixed_numeric_arg_shape_matches:numeric.size() == expectedNumeric.size() && expectedNumeric.every { expected -> numeric.count { it == expected } == 1 },
    file_encoding_utf8:java.nio.charset.Charset.defaultCharset().name() == 'UTF-8']
def bytes = JsonOutput.toJson(facts).getBytes('UTF-8')
if (bytes.length > 2048) throw new GradleException('DEVELOPMENT_VM_FACT_BUDGET')
java.nio.file.Files.newOutputStream(new File(output,'development-jars-build-vm.json').toPath(),java.nio.file.StandardOpenOption.CREATE_NEW,java.nio.file.StandardOpenOption.WRITE).withCloseable { it.write(bytes) }
def events = new File(output,'development-jars-task-events.ndjson')
int count = 0
gradle.taskGraph.afterTask { task, state ->
    count++
    if (count > 512) throw new GradleException('DEVELOPMENT_TASK_COUNT_BUDGET')
    def status = state.failure != null ? 'failed' : state.noSource ? 'no_source' : state.upToDate ? 'up_to_date' : state.skipped ? 'skipped' : state.didWork ? 'executed' : 'no_work'
    def line = JsonOutput.toJson([source_sha:sourceSha,target:target,task:task.path,status:status]) + '\n'
    if (line.getBytes('UTF-8').length > 4096 || events.length()+line.getBytes('UTF-8').length > 65536) throw new GradleException('DEVELOPMENT_TASK_EVENT_BUDGET')
    events.append(line,'UTF-8')
}
'@
        $packageInitText = $packageInitText.Replace('__MMMM_FIXED_NUMERIC_ARGS__', (ConvertTo-Json -InputObject $numericArgs -Compress))
        $initStream = $null; $initFailure = $null
        try {
            $initStream = [System.IO.File]::Open($packageInit, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $initBytes = $utf8.GetBytes($packageInitText)
            if ($initBytes.Length -gt 65536) { throw 'DEVELOPMENT_INIT_BUDGET' }
            $initStream.Write($initBytes,0,$initBytes.Length); $initStream.Flush($true)
        } catch { $initFailure = $_ }
        if ($null -ne $initStream) {
            try { $initStream.Dispose() } catch {
                $failures.Add((Get-SafeFailureRecord $_ 'development_init_stream_close'))
                if ($null -eq $initFailure) { $initFailure = $_ }
            }
        }
        if ($null -ne $initFailure) { throw $initFailure }
        $packageInitPin = Get-DevelopmentPin $packageInit 64KB $failures
        $package.init_script_sha256 = $packageInitPin.sha256
        $operation = 'development_gradle_launch'; $package.phase = 'gradle_tasks'
        $packageArguments = $fixedJvmArgs + @("-javaagent:$gradleAgent",'-cp',$gradleMain,'org.gradle.launcher.GradleMain',
            '--project-dir',(Join-Path $checkoutRoot 'jvm'),'--project-cache-dir',$projectCache,'--init-script',$packageInit,
            '--console=plain','--no-daemon','--no-parallel','--max-workers=2','--no-build-cache','--no-configuration-cache','--rerun-tasks',
            "-Dmmmm.ci.sourceSha=$ExpectedSourceSha","-Dmmmm.developmentJars.target=$Target","-Dmmmm.developmentJars.evidence=$packageRoot",
            '-Dorg.gradle.java.installations.auto-download=false','-Dorg.gradle.java.installations.auto-detect=false',
            "-Dorg.gradle.java.installations.paths=$javaHome","-Dorg.gradle.jvmargs=$buildJvmArgs",':mmmmDevelopmentJars')
        # Gradle text remains console output; it must not become this function's
        # success return value or an artifact selection input.
        & $java @packageArguments | ForEach-Object { [System.Console]::Out.WriteLine([string]$_) }
        $package.gradle_exit = $LASTEXITCODE
        Assert-DevelopmentTime
        $operation = 'development_postcheck'; $package.phase = 'postcheck'
        Assert-DevelopmentSources $inputRecords $failures
        $package.source_post_checked = $true
        foreach ($name in $selected.Keys) { Assert-DevelopmentPin $pins[$name] (Get-DevelopmentPin $selected[$name] 512MB $failures) }
        $package.selected_files_post_checked = $true
        Assert-DevelopmentPin $packageInitPin (Get-DevelopmentPin $packageInit 64KB $failures)
        Assert-DevelopmentPin $verificationPin (Get-DevelopmentPin (Join-Path $evidence 'jvm-result.json') 1MB $failures)
        if ($package.gradle_exit -ne 0) { throw 'DEVELOPMENT_GRADLE_FAILED' }
        $vm = ConvertFrom-Json -InputObject ($utf8.GetString((Read-DevelopmentBytes (Join-Path $packageRoot 'development-jars-build-vm.json') 2048 $failures))) -NoEnumerate
        if ($vm -isnot [System.Management.Automation.PSCustomObject] -or $vm.schema -isnot [string] -or $vm.schema -cne 'mmmm-jvm-development-build-vm/1' -or
            $vm.source_sha -isnot [string] -or $vm.source_sha -cne $ExpectedSourceSha -or $vm.target -isnot [string] -or $vm.target -cne $Target -or
            $vm.gradle_version -isnot [string] -or $vm.gradle_version -cne '9.6.0' -or
            $vm.fixed_numeric_arg_shape_matches -isnot [bool] -or $vm.fixed_numeric_arg_shape_matches -ne $true -or
            $vm.file_encoding_utf8 -isnot [bool] -or $vm.file_encoding_utf8 -ne $true -or
            $vm.max_heap_bytes -isnot [long] -or $vm.input_argument_count -isnot [long] -or
            $vm.max_heap_bytes -le 64MB -or $vm.max_heap_bytes -gt 1GB -or $vm.input_argument_count -lt 19 -or $vm.input_argument_count -gt 64) { throw 'DEVELOPMENT_VM_FACT_INVALID' }
        $package.build_vm = $vm
        $factsRaw = Read-DevelopmentBytes (Join-Path $packageRoot 'development-jars-artifacts.json') 65536 $failures
        $package.archive_facts_sha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($factsRaw)).ToLowerInvariant()
        $factsPin = Get-DevelopmentPin (Join-Path $packageRoot 'development-jars-artifacts.json') 65536 $failures
        if ($factsPin.sha256 -cne $package.archive_facts_sha256) { throw 'DEVELOPMENT_ARCHIVE_FACT_CHANGED' }
        $facts = ConvertFrom-Json -InputObject ($utf8.GetString($factsRaw)) -NoEnumerate
        if ($facts -isnot [System.Management.Automation.PSCustomObject] -or $facts.schema -isnot [string] -or $facts.schema -cne 'mmmm-development-jar-artifacts/1' -or
            $facts.source_sha -isnot [string] -or $facts.source_sha -cne $ExpectedSourceSha -or $facts.target -isnot [string] -or $facts.target -cne $Target -or
            $facts.development_only -isnot [bool] -or $facts.development_only -ne $true -or $facts.artifacts -isnot [array] -or @($facts.artifacts).Count -ne 3) { throw 'DEVELOPMENT_ARCHIVE_FACT_INVALID' }
        if ($IsWindows -ne ($Target -ceq 'windows-x64')) { throw 'DEVELOPMENT_ARCHIVE_IDENTITY_TARGET_MISMATCH' }
        $expectedPhysicalMode = if ($IsWindows) { 'windows-owned-slot-share-guarded' } else { 'basic-file-key' }
        $expectedDirectoryMode = if ($IsWindows) { 'owned-slot-physical-metadata-recheck' } else { 'basic-file-key' }
        if ($facts.physical_identity_mode -isnot [string] -or $facts.physical_identity_mode.Length -gt 64 -or
            $facts.physical_identity_mode -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $facts.physical_identity_mode -cne $expectedPhysicalMode -or
            $facts.directory_identity_mode -isnot [string] -or $facts.directory_identity_mode.Length -gt 64 -or
            $facts.directory_identity_mode -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $facts.directory_identity_mode -cne $expectedDirectoryMode) { throw 'DEVELOPMENT_ARCHIVE_IDENTITY_MODE_INVALID' }
        $package.physical_identity_mode = $facts.physical_identity_mode
        $package.directory_identity_mode = $facts.directory_identity_mode
        $roles = @{fabric_host=':fabric-host';definition_observer=':definition-observer';provider_sdk=':provider-sdk'}
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $pathComparer = if ($IsWindows) { [System.StringComparer]::OrdinalIgnoreCase } else { [System.StringComparer]::Ordinal }
        $paths = [System.Collections.Generic.HashSet[string]]::new($pathComparer)
        $products = [System.Collections.Generic.List[object]]::new(); $total = 0L
        $payloadRoot = Get-NativePath (New-PhysicalDirectory (Join-Path $packageRoot 'payloads')) $true
        foreach ($artifact in $facts.artifacts) {
            if ($artifact -isnot [System.Management.Automation.PSCustomObject] -or $artifact.role -isnot [string] -or
                $artifact.role -cnotin @('fabric_host','definition_observer','provider_sdk') -or -not $seen.Add($artifact.role) -or
                $artifact.project_path -isnot [string] -or $artifact.project_path -cne $roles[$artifact.role] -or
                $artifact.task_path -isnot [string] -or $artifact.task_path -cnotmatch '^:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$' -or
                $artifact.archive_extension -isnot [string] -or $artifact.archive_extension -cne 'jar' -or
                $artifact.classifier -isnot [string] -or $artifact.classifier -cne '' -or
                $artifact.producer_status -isnot [string] -or $artifact.producer_status -cne 'executed' -or
                $artifact.bytes -isnot [long] -or $artifact.bytes -le 0 -or $artifact.bytes -gt 64MB -or $artifact.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $artifact.sha256 -isnot [string] -or $artifact.relative_path -isnot [string] -or
                $artifact.relative_path -cnotmatch '^[A-Za-z0-9_./$+-]+[.]jar$' -or $artifact.relative_path.StartsWith('/') -or
                $artifact.relative_path.Split('/') -contains '..' -or $artifact.relative_path.Split('/') -contains '.') { throw 'DEVELOPMENT_ARCHIVE_ROLE_INVALID' }
            if ($artifact.role -cne 'fabric_host' -and $artifact.task_path -cne ($roles[$artifact.role]+':jar')) { throw 'DEVELOPMENT_EXACT_JAR_TASK_REQUIRED' }
            if (-not $artifact.task_path.StartsWith($roles[$artifact.role]+':',[System.StringComparison]::Ordinal) -or
                -not $artifact.relative_path.StartsWith($roles[$artifact.role].Substring(1)+'/',[System.StringComparison]::Ordinal)) { throw 'DEVELOPMENT_ARCHIVE_PROJECT_MISMATCH' }
            $source = Get-NativePath (Join-Path $gradleBuild $artifact.relative_path) $false
            if (-not (Is-Inside $source $gradleBuild) -or -not $paths.Add($source)) { throw 'DEVELOPMENT_ARCHIVE_PATH_INVALID' }
            $total += $artifact.bytes
            if ($total -gt 192MB) { throw 'DEVELOPMENT_ARCHIVE_AGGREGATE_BUDGET' }
            $roleRoot = Get-NativePath (New-PhysicalDirectory (Join-Path $payloadRoot $artifact.role)) $true
            $name = [System.IO.Path]::GetFileName($source)
            $copy = Copy-DevelopmentJar $source (Join-Path $roleRoot $name) $artifact $failures
            $products.Add([ordered]@{role=$artifact.role;producer_task=$artifact.task_path;path=('payloads/'+$artifact.role+'/'+$name);bytes=$copy.bytes;sha256=$copy.sha256})
        }
        if ($seen.Count -ne 3) { throw 'DEVELOPMENT_ARCHIVE_ROLES_INCOMPLETE' }
        $package.artifacts = $products.ToArray()
        $package.task_events_sha256 = (Get-DevelopmentPin (Join-Path $packageRoot 'development-jars-task-events.ndjson') 65536 $failures).sha256
        Assert-DevelopmentSources $inputRecords $failures
        foreach ($name in $selected.Keys) { Assert-DevelopmentPin $pins[$name] (Get-DevelopmentPin $selected[$name] 512MB $failures) }
        Assert-DevelopmentPin $packageInitPin (Get-DevelopmentPin $packageInit 64KB $failures)
        Assert-DevelopmentPin $verificationPin (Get-DevelopmentPin (Join-Path $evidence 'jvm-result.json') 1MB $failures)
        Assert-DevelopmentPin $factsPin (Get-DevelopmentPin (Join-Path $packageRoot 'development-jars-artifacts.json') 65536 $failures)
        $package.phase = 'complete'; $package.status = 'passed'; $success = $true
    } catch {
        $package.status = 'failed'; $package.failure_details = @((Get-SafeFailureRecord $_ $operation))
        [System.Console]::Error.WriteLine('DEVELOPMENT_JARS_FAILED')
        $primaryJson = ConvertTo-Json -InputObject $package.failure_details[0] -Depth 8 -Compress
        if ($utf8.GetByteCount($primaryJson) -le 4096) { [System.Console]::Error.WriteLine($primaryJson) }
    } finally {
        $package.failure_details += $failures.ToArray()
        if ($null -ne $packageRoot) {
            $exportFailureStart = $failures.Count
            try { Write-DevelopmentResult $packageRoot $package $failures }
            catch {
                $success = $false
                [System.Console]::Error.WriteLine('DEVELOPMENT_JARS_RESULT_EXPORT_FAILED')
                $failureBytes = $utf8.GetBytes((ConvertTo-Json -InputObject (Get-SafeFailureRecord $_ 'development_result_export') -Depth 8 -Compress))
                if ($failureBytes.Length -le 4096) { [System.Console]::Error.WriteLine($utf8.GetString($failureBytes)) }
                for ($index = $exportFailureStart; $index -lt [System.Math]::Min($failures.Count,$exportFailureStart+8); $index++) {
                    $secondary = ConvertTo-Json -InputObject $failures[$index] -Depth 8 -Compress
                    if ($utf8.GetByteCount($secondary) -le 4096) { [System.Console]::Error.WriteLine($secondary) }
                }
            }
        }
        $phase = $savedPhase; $operation = $savedOperation
    }
    return $success
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'POWERSHELL_7_REQUIRED' }
    $useGeneration = $PSBoundParameters.ContainsKey('ToolchainGeneration')
    $generation = $null
    if ($useGeneration) {
        if ($ToolchainGeneration -cnotmatch '^[0-9a-f]{40}$' -or $ToolchainGeneration -cne $ExpectedSourceSha) { throw 'JVM_TOOLCHAIN_GENERATION_SOURCE_MISMATCH' }
        $generation = $ToolchainGeneration
    }
    $record.toolchain_generation = $generation
    $checkoutRoot = Assert-PhysicalPath $Checkout $true
    $evidence = Assert-PhysicalPath $EvidenceRoot $true
    $operation = 'runtime_preflight'
    . (Join-Path $checkoutRoot 'tools/bootstrap/jvm-runtime-probe.ps1')
    $runtimeProbe = Get-MmmmJvmRuntimeProbe -SourceSha $ExpectedSourceSha -Target $Target -Scope inside
    # The managed Rust route must supply this fixed override before pwsh starts.
    # Setting it here cannot prevent the CLR startup debugger FIFO. Export only
    # the observed policy boolean, never inherited environment values.
    $runtimeProbe['managed_helper_diagnostics_disabled'] =
        ([System.Environment]::GetEnvironmentVariable('DOTNET_EnableDiagnostics', [System.EnvironmentVariableTarget]::Process) -ceq '0')
    Write-NewJson (Join-Path $evidence 'jvm-runtime-inside.json') $runtimeProbe 16384
    $record.runtime_probe_sha256 = Get-RegularHash (Join-Path $evidence 'jvm-runtime-inside.json') 16384
    $operation = 'managed_diagnostics_policy'
    if (-not $runtimeProbe['managed_helper_diagnostics_disabled']) { throw 'MANAGED_JVM_DIAGNOSTICS_POLICY_REQUIRED' }
    $operation = 'managed_gradle_user_home'
    $managedGradleHome = Assert-PhysicalPath $env:GRADLE_USER_HOME $true
    $scratch = Assert-PhysicalPath $env:TMP $true
    $cache = Assert-PhysicalPath ([System.IO.Path]::GetDirectoryName($managedGradleHome)) $true
    if ([System.IO.Path]::GetFileName($managedGradleHome) -cne 'gradle-user-home' -or [System.IO.Path]::GetFileName($cache) -cne 'cache') { throw 'MANAGED_JVM_CACHE_REQUIRED' }
    $slot = Assert-PhysicalPath ([System.IO.Path]::GetDirectoryName($cache)) $true
    if ([System.IO.Path]::GetFileName($slot) -cnotmatch '^(windows|linux|macos)-(x86_64|aarch64)-[0-9a-f]{24}-jvm$' -or
        -not (Is-Inside $scratch $slot) -or (Is-Inside $cache $checkoutRoot) -or (Is-Inside $evidence $checkoutRoot) -or (Is-Inside $evidence $slot)) { throw 'MANAGED_JVM_PATH_BOUNDARY_INVALID' }
    $projectCache = Assert-PhysicalPath (Join-Path $cache 'gradle-project-cache') $true
    $gradleBuild = Assert-PhysicalPath (Join-Path $cache 'gradle-build') $true
    $actualTarget = if ($IsWindows -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'windows-x64' }
        elseif ($IsLinux -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'X64') { 'linux-x64' }
        elseif ($IsMacOS -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64') { 'macos-arm64' }
        else { throw 'UNSUPPORTED_JVM_TARGET' }
    if ($actualTarget -cne $Target) { throw 'JVM_TARGET_MISMATCH' }
    $operation = 'native_path_identity'
    if ($IsWindows) { Add-Type -Path (Join-Path $checkoutRoot 'tools/bootstrap/WindowsBootstrap.cs') }
    $checkoutRoot = Get-NativePath $checkoutRoot $true
    $evidence = Get-NativePath $evidence $true
    $managedGradleHome = Get-NativePath $managedGradleHome $true
    $scratch = Get-NativePath $scratch $true
    $projectCache = Get-NativePath $projectCache $true
    $gradleBuild = Get-NativePath $gradleBuild $true
    $pythonProgram = Get-NativePath $Python $false
    foreach ($optionName in @('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','GRADLE_OPTS')) {
        if ($null -ne [System.Environment]::GetEnvironmentVariable($optionName)) { throw 'UNREGISTERED_JVM_OPTION_OVERRIDE' }
    }
    $operation = 'source_input_identity'
    $sourceSha = @(& git -C $checkoutRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sourceSha.Count -ne 1 -or $sourceSha[0] -cne $ExpectedSourceSha) { throw 'SOURCE_SHA_MISMATCH' }
    & git -C $checkoutRoot diff --quiet HEAD -- jvm contracts examples tests/example-index.json tests/digest-fixtures.json tools/bootstrap/jvm-ci.ps1 tools/bootstrap/jvm-runtime-probe.ps1 tools/bootstrap/jvm-archive.py .github/workflows/jvm.yml tools/bootstrap/WindowsBootstrap.cs
    if ($LASTEXITCODE -ne 0) { throw 'DIRTY_JVM_SOURCE_INPUTS' }
    $inputs = @(& git -C $checkoutRoot ls-files -- jvm contracts examples tests/example-index.json tests/digest-fixtures.json tools/bootstrap/jvm-ci.ps1 tools/bootstrap/jvm-runtime-probe.ps1 tools/bootstrap/jvm-archive.py .github/workflows/jvm.yml tools/bootstrap/WindowsBootstrap.cs)
    if ($LASTEXITCODE -ne 0 -or $inputs.Count -lt 8 -or $inputs.Count -gt 10000) { throw 'SOURCE_INPUT_INVENTORY_INVALID' }
    $inputRecords = [System.Collections.Generic.List[object]]::new(); $inputBytes = 0L
    foreach ($relative in ($inputs | Sort-Object -CaseSensitive)) {
        if ($relative -cnotmatch '^[A-Za-z0-9_./$-]+$' -or $relative -match '(?i)(^|/)(\.env(?:\.[^/]*)?|.*credential[^/]*|.*service[_-]account[^/]*|id_rsa[^/]*|id_ed25519[^/]*|node_modules|dist|dist-server|build|coverage|models|checkpoints|\.cache|\.gradle)(/|$)' -or
            $relative -match '(?i)\.(pem|key|p12|pfx)$' -or $relative.Contains('..')) { throw 'DISALLOWED_SOURCE_INPUT_PATH' }
        $sourceFile = Assert-PhysicalPath (Join-Path $checkoutRoot $relative) $false
        if (-not (Is-Inside $sourceFile $checkoutRoot)) { throw 'SOURCE_INPUT_ESCAPE' }
        $bytes = [System.IO.FileInfo]::new($sourceFile).Length
        $inputBytes += $bytes
        if ($inputBytes -gt 128MB) { throw 'SOURCE_INPUT_AGGREGATE_BUDGET_EXCEEDED' }
        $inputRecords.Add([ordered]@{ path=$relative; bytes=$bytes; sha256=(Get-RegularHash $sourceFile 10MB) })
    }
    Write-NewJson (Join-Path $evidence 'jvm-source-inputs.json') ([ordered]@{ schema='mmmm-jvm-source-inputs/1'; source_sha=$ExpectedSourceSha; inputs=$inputRecords.ToArray() }) 1MB
    $record.source_inputs_sha256 = Get-RegularHash (Join-Path $evidence 'jvm-source-inputs.json') 1MB
    $phase = 'pinned_toolchains'
    $operation = 'pinned_archive_download_and_extraction'
    $jdkProfiles = @{
        'windows-x64' = @{ file='OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip'; sha='00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283'; java='jdk-25.0.4.1+1/bin/java.exe' }
        'linux-x64' = @{ file='OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz'; sha='dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e'; java='jdk-25.0.4.1+1/bin/java' }
        'macos-arm64' = @{ file='OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4.1_1.tar.gz'; sha='61979887f7506a24a57439ff99adb8b3a7fc89977d9cfe3b8984f58a981b7b9d'; java='jdk-25.0.4.1+1/Contents/Home/bin/java' }
    }
    $jdk = $jdkProfiles[$Target]
    $toolchains = New-ToolchainOutput (Join-Path $gradleBuild 'ci-toolchains') $jdk.file $useGeneration $generation
    $archiveTool = Get-NativePath (Join-Path $checkoutRoot 'tools/bootstrap/jvm-archive.py') $false
    $profiles = @(
        @{ name='temurin'; file=$jdk.file; sha=$jdk.sha; root='jdk-25.0.4.1+1'; url="https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/$($jdk.file)" },
        @{ name='gradle'; file='gradle-9.6.0-bin.zip'; sha='bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01'; root='gradle-9.6.0'; url='https://services.gradle.org/distributions/gradle-9.6.0-bin.zip' }
    )
    $toolchainRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($profile in $profiles) {
        $archive = Join-Path $toolchains $profile.file
        $archiveBytes = Get-PinnedArchive $profile.url $archive $profile.sha
        $destination = Join-Path $toolchains $profile.name
        $extractionLines = @(& $pythonProgram -B $archiveTool --archive $archive --sha256 $profile.sha --destination $destination --root $profile.root)
        if ($LASTEXITCODE -ne 0 -or $extractionLines.Count -ne 1 -or $utf8.GetByteCount($extractionLines[0]) -gt 4096) { throw 'TOOLCHAIN_EXTRACTION_FAILED' }
        $extraction = $extractionLines[0] | ConvertFrom-Json
        if ($extraction.schema -cne 'mmmm-jvm-extraction/1' -or $extraction.archive_sha256 -cne $profile.sha -or $extraction.root -cne $profile.root) { throw 'TOOLCHAIN_EXTRACTION_RECEIPT_INVALID' }
        $toolchainRecords.Add([ordered]@{ name=$profile.name; archive=$profile.file; source_url=$profile.url; sha256=$profile.sha;
            archive_bytes=$archiveBytes; extraction=$extraction })
    }
    Write-NewJson (Join-Path $evidence 'jvm-toolchains.json') ([ordered]@{ schema='mmmm-jvm-toolchains/1'; target=$Target;
        source_sha=$ExpectedSourceSha; toolchain_generation=$generation; toolchains=$toolchainRecords.ToArray() })
    $java = Get-NativePath (Join-Path (Join-Path $toolchains 'temurin') $jdk.java) $false
    $javaHome = Get-NativePath ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($java))) $true
    $releaseFile = Get-NativePath (Join-Path $javaHome 'release') $false
    if ([System.IO.FileInfo]::new($releaseFile).Length -gt 64KB) { throw 'JDK_RELEASE_RECORD_BUDGET' }
    $releaseText = [System.IO.File]::ReadAllText($releaseFile, $utf8)
    if ($releaseText -cnotmatch '(?m)^JAVA_VERSION="25\.0\.4\.1"\r?$' -or $releaseText -cnotmatch '(?m)^IMPLEMENTOR="Eclipse Adoptium"\r?$' -or
        $releaseText -cnotmatch '(?m)^JAVA_RUNTIME_VERSION="25\.0\.4\.1\+1[^"\r\n]*"\r?$') { throw 'PINNED_JDK_RELEASE_MISMATCH' }
    $record.jdk_release_sha256 = Get-RegularHash $releaseFile 64KB
    $gradleMain = Get-NativePath (Join-Path $toolchains 'gradle/gradle-9.6.0/lib/gradle-gradle-cli-main-9.6.0.jar') $false
    $gradleAgent = Get-NativePath (Join-Path $toolchains 'gradle/gradle-9.6.0/lib/agents/gradle-instrumentation-agent-9.6.0.jar') $false
    $operation = 'gradle_agent_precheck'
    $agentPin = Get-GradleAgentPin $gradleAgent
    # This is an observed component digest from the already pinned distribution,
    # checked again after Java returns; it is not an independent upstream digest.
    $record.gradle_agent = [ordered]@{ relative_path='lib/agents/gradle-instrumentation-agent-9.6.0.jar'; bytes=$agentPin.bytes; sha256=$agentPin.sha256; post_checked=$false }
    $env:JAVA_HOME = $javaHome
    $env:GRADLE_USER_HOME = $managedGradleHome
    $env:TMP = $scratch; $env:TEMP = $scratch; $env:TMPDIR = $scratch
    $phase = 'gradle_tasks'
    $operation = 'required_gradle_tasks'
    $taskEvidence = Join-Path $evidence 'jvm-task-events.ndjson'
    $classpathEvidence = Join-Path $evidence 'jvm-classpath-inputs.ndjson'
    foreach ($newEvidence in @($taskEvidence, $classpathEvidence)) {
        $stream = [System.IO.File]::Open($newEvidence, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Dispose()
    }
    $init = Join-Path $scratch 'jvm-ci.init.gradle'
    # Gradle v9.6.0 (3f750f03d77e42327c5f9fcb9992110088330a32):
    # JpmsConfiguration.forDaemonProcesses(25, true), plus the existing build caps.
    # The client and requested build VM consume this one array. Compatibility
    # still depends on the actual JVM and agent; matching args is not a daemon-mode fact.
    $fixedJvmArgs = @('-Xms128m','-Xmx1g','-XX:MaxMetaspaceSize=384m','-Dfile.encoding=UTF-8',
        "-Djava.io.tmpdir=$scratch", "-XX:ErrorFile=$gradleBuild/jvm-fatal-%p.log",
        '--add-opens=java.base/java.lang=ALL-UNNAMED','--add-opens=java.base/java.lang.invoke=ALL-UNNAMED',
        '--add-opens=java.base/java.util=ALL-UNNAMED','--add-opens=java.prefs/java.util.prefs=ALL-UNNAMED',
        '--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED','--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
        '--add-opens=java.base/java.nio.charset=ALL-UNNAMED','--add-opens=java.base/java.net=ALL-UNNAMED',
        '--add-opens=java.base/java.util.concurrent=ALL-UNNAMED','--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED',
        '--add-opens=java.xml/javax.xml.namespace=ALL-UNNAMED','--add-opens=java.base/java.time=ALL-UNNAMED',
        '--enable-native-access=ALL-UNNAMED')
    if ($fixedJvmArgs.Count -ne $record.profile.fixed_jvm_argument_count) { throw 'FIXED_JVM_ARGUMENT_COUNT' }
    foreach ($argument in $fixedJvmArgs) {
        # Gradle's ArgumentsSplitter supports quoted tokens, but not escaped quotes.
        if ($argument -cmatch '["\x00-\x1f\x7f]' -or $utf8.GetByteCount($argument) -gt 4096) { throw 'FIXED_JVM_ARGUMENT_ENCODING' }
    }
    $buildJvmArgs = ($fixedJvmArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    if ($utf8.GetByteCount($buildJvmArgs) -gt 16KB) { throw 'FIXED_JVM_ARGUMENT_BUDGET' }
    $initText = @'
import groovy.json.JsonOutput
import java.security.MessageDigest
def selected = __MMMM_REQUIRED_TASKS__
def evidence = new File(System.getProperty('mmmm.ci.evidence'))
def events = new File(evidence, 'jvm-task-events.ndjson')
def inputs = new File(evidence, 'jvm-classpath-inputs.ndjson')
def sourceSha = System.getProperty('mmmm.ci.sourceSha')
// Facts from the JVM evaluating this init script, not a daemon/client identity proof.
def expectedNumeric = __MMMM_FIXED_NUMERIC_ARGS__
def actualArgs = java.lang.management.ManagementFactory.runtimeMXBean.inputArguments
if (actualArgs.size() > 64 || actualArgs.any { it.getBytes('UTF-8').length > 4096 } || actualArgs.sum { it.getBytes('UTF-8').length } > 16384) throw new GradleException('JVM_ARGUMENT_OBSERVATION_BUDGET')
def numeric = actualArgs.findAll { it.startsWith('-Xms') || it.startsWith('-Xmx') || it.startsWith('-XX:MaxMetaspaceSize=') }
def vmFacts = [schema:'mmmm-jvm-build-vm/1', source_sha:sourceSha, gradle_version:org.gradle.util.GradleVersion.current().version,
    max_heap_bytes:Runtime.runtime.maxMemory(), input_argument_count:actualArgs.size(),
    fixed_numeric_arg_shape_matches:numeric.size() == expectedNumeric.size() && expectedNumeric.every { expected -> numeric.count { it == expected } == 1 },
    file_encoding_utf8:java.nio.charset.Charset.defaultCharset().name() == 'UTF-8']
def vmBytes = (JsonOutput.toJson(vmFacts) + '\n').getBytes('UTF-8')
if (vmBytes.length > 2048) throw new GradleException('JVM_BUILD_VM_EVIDENCE_BUDGET')
java.nio.file.Files.newOutputStream(new File(evidence, 'jvm-build-vm.json').toPath(), java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE).withCloseable { it.write(vmBytes) }
gradle.taskGraph.beforeTask { task ->
    if (!selected.contains(task.path)) return
    if (!(task instanceof org.gradle.api.tasks.compile.JavaCompile) && !(task instanceof org.gradle.api.tasks.testing.Test)) return
    def classpath = task.classpath.files
    def jars = classpath.findAll { it.name.endsWith('.jar') }
    if (jars.size() > 1024) throw new GradleException('JVM_CLASSPATH_ENTRY_BUDGET')
    long total = 0
    classpath.eachWithIndex { jar, index ->
        if (!jar.name.endsWith('.jar')) return
        if (!jar.isFile() || java.nio.file.Files.isSymbolicLink(jar.toPath()) || jar.length() > 512L * 1024 * 1024) throw new GradleException('JVM_CLASSPATH_FILE_INVALID')
        def before = java.nio.file.Files.readAttributes(jar.toPath(), java.nio.file.attribute.BasicFileAttributes, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        if (!before.isRegularFile()) throw new GradleException('JVM_CLASSPATH_FILE_INVALID')
        total += before.size()
        if (total > 2L * 1024 * 1024 * 1024) throw new GradleException('JVM_CLASSPATH_BYTES_BUDGET')
        def sha = MessageDigest.getInstance('SHA-256')
        jar.withInputStream { stream ->
            byte[] buffer = new byte[65536]; int count; long observed = 0
            while ((count = stream.read(buffer)) != -1) {
                observed += count
                if (observed > before.size() || observed > 512L * 1024 * 1024) throw new GradleException('JVM_CLASSPATH_READ_BUDGET')
                sha.update(buffer, 0, count)
            }
            if (observed != before.size()) throw new GradleException('JVM_CLASSPATH_SIZE_CHANGED')
        }
        def after = java.nio.file.Files.readAttributes(jar.toPath(), java.nio.file.attribute.BasicFileAttributes, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        if (!after.isRegularFile() || before.fileKey() != after.fileKey() || before.size() != after.size() || before.lastModifiedTime() != after.lastModifiedTime()) throw new GradleException('JVM_CLASSPATH_IDENTITY_CHANGED')
        def line = JsonOutput.toJson([source_sha: sourceSha, task: task.path, classpath_index: index, classpath_entries: classpath.size(), unhashed_directory_entries: classpath.count { it.isDirectory() }, name: jar.name, bytes: before.size(), sha256: sha.digest().encodeHex().toString()]) + '\n'
        if (line.getBytes('UTF-8').length > 4096 || inputs.length() + line.getBytes('UTF-8').length > 1024 * 1024) throw new GradleException('JVM_CLASSPATH_EVIDENCE_BUDGET')
        inputs.append(line, 'UTF-8')
    }
}
gradle.taskGraph.afterTask { task, state ->
    if (!selected.contains(task.path)) return
    def status = state.failure != null ? 'failed' : state.noSource ? 'no_source' : state.upToDate ? 'up_to_date' : state.skipped ? 'skipped' : state.didWork ? 'executed' : 'no_work'
    def line = JsonOutput.toJson([source_sha: sourceSha, task: task.path, status: status]) + '\n'
    if (events.length() + line.getBytes('UTF-8').length > 65536) throw new GradleException('JVM_TASK_EVIDENCE_BUDGET')
    events.append(line, 'UTF-8')
}
'@
    # JSON arrays with the fixed task names are valid Groovy list literals.
    # Use the command's own required list for both task selection and evidence.
    $initText = $initText.Replace('__MMMM_REQUIRED_TASKS__', (ConvertTo-Json -InputObject $tasks -Compress))
    $numericArgs = @($fixedJvmArgs | Where-Object { $_ -cmatch '^(-Xms|-Xmx|-XX:MaxMetaspaceSize=)' })
    $initText = $initText.Replace('__MMMM_FIXED_NUMERIC_ARGS__', (ConvertTo-Json -InputObject $numericArgs -Compress))
    [System.IO.File]::WriteAllText($init, $initText, $utf8)
    $record.init_script_sha256 = Get-RegularHash $init 64KB
    # CurrentProcess filters Gradle's own agent switch before comparing immutable
    # args. Keep it launcher-only; placing it in org.gradle.jvmargs would mismatch.
    $arguments = $fixedJvmArgs + @("-javaagent:$gradleAgent", '-cp',$gradleMain,
        'org.gradle.launcher.GradleMain','--project-dir',(Join-Path $checkoutRoot 'jvm'),'--project-cache-dir',$projectCache,
        '--init-script',$init,'--console=plain','--no-daemon','--no-parallel','--max-workers=2','--no-build-cache','--no-configuration-cache',
        '--rerun-tasks','--continue', "-Dmmmm.ci.evidence=$evidence", "-Dmmmm.ci.sourceSha=$ExpectedSourceSha",
        '-Dorg.gradle.java.installations.auto-download=false', '-Dorg.gradle.java.installations.auto-detect=false',
        "-Dorg.gradle.java.installations.paths=$javaHome", "-Dorg.gradle.jvmargs=$buildJvmArgs") + $tasks
    & $java @arguments
    $nativeExit = $LASTEXITCODE
    $record.gradle_exit = $nativeExit
    $operation = 'gradle_agent_postcheck'
    $agentAfter = Get-GradleAgentPin $gradleAgent
    if ($agentAfter.bytes -ne $agentPin.bytes -or $agentAfter.sha256 -cne $agentPin.sha256 -or $agentAfter.modified -ne $agentPin.modified -or $agentAfter.created -ne $agentPin.created) { throw 'GRADLE_AGENT_PIN_CHANGED' }
    $record.gradle_agent.post_checked = $true
    $phase = 'evidence_export'
    $operation = 'source_and_test_evidence'
    $buildVmPath = Get-NativePath (Join-Path $evidence 'jvm-build-vm.json') $false
    if ([System.IO.FileInfo]::new($buildVmPath).Length -gt 2048) { throw 'JVM_BUILD_VM_EVIDENCE_BUDGET' }
    $buildVm = [System.IO.File]::ReadAllText($buildVmPath, $utf8) | ConvertFrom-Json
    $vmFields = @('schema','source_sha','gradle_version','max_heap_bytes','input_argument_count','fixed_numeric_arg_shape_matches','file_encoding_utf8')
    if (@($buildVm.PSObject.Properties).Count -ne $vmFields.Count -or @($buildVm.PSObject.Properties | Where-Object { $_.Name -cnotin $vmFields }).Count -ne 0 -or
        $buildVm.schema -cne 'mmmm-jvm-build-vm/1' -or $buildVm.source_sha -cne $ExpectedSourceSha -or $buildVm.gradle_version -cne '9.6.0' -or
        $buildVm.max_heap_bytes -isnot [long] -or $buildVm.max_heap_bytes -le 64MB -or $buildVm.max_heap_bytes -gt $record.profile.daemon_heap_bytes -or
        $buildVm.input_argument_count -isnot [long] -or $buildVm.input_argument_count -lt $fixedJvmArgs.Count -or $buildVm.input_argument_count -gt 64 -or
        $buildVm.fixed_numeric_arg_shape_matches -isnot [bool] -or $buildVm.fixed_numeric_arg_shape_matches -ne $true -or
        $buildVm.file_encoding_utf8 -isnot [bool] -or $buildVm.file_encoding_utf8 -ne $true) { throw 'JVM_BUILD_VM_EVIDENCE_INVALID' }
    $record.build_vm = $buildVm
    $record.build_vm_probe_sha256 = Get-RegularHash $buildVmPath 2048
    $finalSourceSha = @(& git -C $checkoutRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $finalSourceSha.Count -ne 1 -or $finalSourceSha[0] -cne $ExpectedSourceSha) { throw 'SOURCE_SHA_CHANGED_DURING_BUILD' }
    & git -C $checkoutRoot diff --quiet HEAD -- jvm contracts examples tests/example-index.json tests/digest-fixtures.json tools/bootstrap/jvm-ci.ps1 tools/bootstrap/jvm-runtime-probe.ps1 tools/bootstrap/jvm-archive.py .github/workflows/jvm.yml tools/bootstrap/WindowsBootstrap.cs
    if ($LASTEXITCODE -ne 0) { throw 'SOURCE_CHANGED_DURING_BUILD' }
    foreach ($inputRecord in $inputRecords) {
        $finalFile = Assert-PhysicalPath (Join-Path $checkoutRoot $inputRecord.path) $false
        if ([System.IO.FileInfo]::new($finalFile).Length -ne $inputRecord.bytes -or (Get-RegularHash $finalFile 10MB) -cne $inputRecord.sha256) { throw 'SOURCE_INPUT_CHANGED_DURING_BUILD' }
    }
    if ([System.IO.FileInfo]::new($taskEvidence).Length -gt 64KB) { throw 'TASK_EVIDENCE_BUDGET_EXCEEDED' }
    $events = @(Get-Content -LiteralPath $taskEvidence | ForEach-Object { $_ | ConvertFrom-Json })
    foreach ($event in $events) {
        if ($event.source_sha -cne $ExpectedSourceSha -or $event.task -cnotin $tasks -or $event.status -cnotin @('failed','no_source','up_to_date','skipped','executed','no_work')) { throw 'TASK_EVIDENCE_INVALID' }
    }
    if (@($events | Group-Object task | Where-Object Count -ne 1).Count -ne 0) { throw 'DUPLICATE_TASK_EVIDENCE' }
    $record.tasks = $events
    $testSummaries = [System.Collections.Generic.List[object]]::new()
    foreach ($module in $testModules) {
        $event = @($events | Where-Object task -CEQ ":${module}:test")
        if ($event.Count -eq 1 -and $event[0].status -cin @('executed','failed')) {
            try { $testSummaries.Add((Export-TestSummary $module (Join-Path $gradleBuild "$module/test-results/test"))) }
            catch {
                $record.evidence_errors += "$module/TEST_REPORT_EXPORT_FAILED"
                $record.failure_details += Get-SafeFailureRecord $_ "$module/test_report_export"
            }
        }
    }
    $record.tests = $testSummaries.ToArray()
    $record.classpath_inputs_sha256 = Get-RegularHash $classpathEvidence 1MB
    $allExecuted = $events.Count -eq $tasks.Count -and @($events | Where-Object status -CNE 'executed').Count -eq 0
    $allTests = $testSummaries.Count -eq $testModules.Count -and @($testSummaries | Where-Object passed -NE $true).Count -eq 0
    $record.status = if ($nativeExit -eq 0 -and $allExecuted -and $allTests -and $record.evidence_errors.Count -eq 0) { 'passed' } else { 'failed' }
    $record.phase = $phase
    Write-NewJson (Join-Path $evidence 'jvm-result.json') $record 1MB
    if ($record.status -cne 'passed') { exit 1 }
    if ($DevelopmentJars -and -not (Invoke-DevelopmentJars)) { exit 1 }
    exit 0
} catch {
    $jvmFailure = $_
    $record.status = 'failed'; $record.phase = $phase; $record.gradle_exit = $nativeExit
    $record.evidence_errors += 'JVM_INFRASTRUCTURE_FAILED/' + $jvmFailure.Exception.GetType().Name
    $failureDetail = Get-SafeFailureRecord $jvmFailure $operation
    $record.failure_details += $failureDetail
    if (Get-Variable -Name evidence -ErrorAction SilentlyContinue) {
        try { Write-NewJson (Join-Path $evidence 'jvm-result.json') $record 1MB } catch { }
    }
    [System.Console]::Error.WriteLine("JVM_CI_FAILED/$phase")
    $failureJson = ConvertTo-Json -InputObject $failureDetail -Depth 8 -Compress
    if ($utf8.GetByteCount($failureJson) -le 4096) { [System.Console]::Error.WriteLine($failureJson) }
    exit 1
}
