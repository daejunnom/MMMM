# Shared, read-only JVM infrastructure diagnostics. This file does not launch a
# child, modify globalization settings, install dependencies or change quotas.
function Get-MmmmJvmRuntimeProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceSha,
        [Parameter(Mandatory)][ValidateSet('windows-x64','linux-x64','macos-arm64')][string]$Target,
        [Parameter(Mandatory)][ValidateSet('outside','inside')][string]$Scope
    )
    $probe = [ordered]@{ schema='mmmm-jvm-runtime-probe/1'; source_sha=$SourceSha; target=$Target; scope=$Scope;
        powershell_version=$PSVersionTable.PSVersion.ToString(); framework=[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription;
        architecture=[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();
        globalization=[ordered]@{ status='not_run'; culture='en-US'; comparison=$null; sort_key_bytes=$null; exception_type=$null; hresult=$null };
        gc_configuration=@{}; linux=[ordered]@{ status='not_applicable'; vm_size_bytes=$null; rss_bytes=$null;
            address_space_soft_bytes=$null; address_space_hard_bytes=$null; loaded_icu_files=@(); exception_type=$null; hresult=$null } }

    try {
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
        $comparison = $culture.CompareInfo.Compare([string][char]0x00E4, 'z', [System.Globalization.CompareOptions]::None)
        $key = $culture.CompareInfo.GetSortKey('MMMM', [System.Globalization.CompareOptions]::None)
        $probe.globalization.comparison = $comparison
        $probe.globalization.sort_key_bytes = $key.KeyData.Length
        $probe.globalization.status = if ($culture.Name -ceq 'en-US' -and $comparison -lt 0 -and $key.KeyData.Length -gt 0) { 'passed' } else { 'unexpected_result' }
    } catch {
        $probe.globalization.status = 'failed'
        $probe.globalization.exception_type = $_.Exception.GetType().FullName
        $probe.globalization.hresult = $_.Exception.HResult
    }

    # Only documented numeric GC settings are exported; no environment dump or
    # arbitrary AppContext values become evidence.
    if (@([System.GC].GetMethods() | Where-Object Name -CEQ 'GetConfigurationVariables').Count -eq 1) {
        $variables = [System.GC]::GetConfigurationVariables()
        foreach ($name in @('GCRegionRange','GCHeapHardLimit','GCHeapHardLimitSOH','GCHeapHardLimitLOH','GCHeapHardLimitPOH','GCHeapHardLimitPercent')) {
            if ($variables.ContainsKey($name)) {
                $number = 0UL
                if ([ulong]::TryParse([string]$variables[$name], [ref]$number)) { $probe.gc_configuration[$name] = $number }
            }
        }
    }

    if ($IsLinux) {
        try {
            $proc = @{}
            foreach ($entry in @(@{ name='status'; bytes=65536 }, @{ name='limits'; bytes=65536 }, @{ name='maps'; bytes=1048576 })) {
                # These three fixed paths describe this process. Never follow a
                # caller-supplied proc path or inspect another process.
                $stream = [System.IO.File]::Open("/proc/self/$($entry.name)", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $memory = [System.IO.MemoryStream]::new()
                try {
                    $buffer = [byte[]]::new(4096)
                    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($memory.Length + $count -gt $entry.bytes) { throw 'PROC_RECORD_BUDGET_EXCEEDED' }
                        $memory.Write($buffer, 0, $count)
                    }
                    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($memory.ToArray())
                    $proc[$entry.name] = $text
                } finally { $memory.Dispose(); $stream.Dispose() }
            }
            foreach ($field in @(@{ name='VmSize'; output='vm_size_bytes' }, @{ name='VmRSS'; output='rss_bytes' })) {
                $match = [System.Text.RegularExpressions.Regex]::Match($proc.status, "(?m)^$($field.name):\s+([0-9]{1,16})\s+kB\s*$")
                if (-not $match.Success) { throw 'PROC_MEMORY_FIELD_INVALID' }
                $kilobytes = [ulong]::Parse($match.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
                if ($kilobytes -gt 18014398509481983UL) { throw 'PROC_MEMORY_FIELD_OVERFLOW' }
                $probe.linux[$field.output] = $kilobytes * 1024UL
            }
            $limit = [System.Text.RegularExpressions.Regex]::Match($proc.limits, '(?m)^Max address space\s+(unlimited|[0-9]{1,20})\s+(unlimited|[0-9]{1,20})\s+bytes\s*$')
            if (-not $limit.Success) { throw 'PROC_ADDRESS_SPACE_FIELD_INVALID' }
            foreach ($field in @(@{ index=1; output='address_space_soft_bytes' }, @{ index=2; output='address_space_hard_bytes' })) {
                $value = $limit.Groups[$field.index].Value
                $probe.linux[$field.output] = if ($value -ceq 'unlimited') { 'unlimited' } else { [ulong]::Parse($value, [System.Globalization.CultureInfo]::InvariantCulture) }
            }
            $icu = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($line in $proc.maps.Split([char]10)) {
                $match = [System.Text.RegularExpressions.Regex]::Match($line, '/(libicu(?:uc|i18n|data)\.so\.[0-9.]{1,32})(?:\s+\(deleted\))?\s*$')
                if ($match.Success) { $null = $icu.Add($match.Groups[1].Value) }
                if ($icu.Count -gt 16) { throw 'LOADED_ICU_FILE_COUNT_EXCEEDED' }
            }
            $probe.linux.loaded_icu_files = @($icu)
            $probe.linux.status = 'observed'
        } catch {
            $probe.linux.status = 'failed'
            $probe.linux.exception_type = $_.Exception.GetType().FullName
            $probe.linux.hresult = $_.Exception.HResult
        }
    }
    if ([System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $probe -Depth 8 -Compress)) -gt 16384) { throw 'RUNTIME_PROBE_RECORD_BUDGET_EXCEEDED' }
    return $probe
}
