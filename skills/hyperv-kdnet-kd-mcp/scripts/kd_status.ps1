# kd.exe / debug-port status: bind holders + command lines + parents
# Use before a kd-mcp attach to find a zombie holding the debug port
# (kd_launch.py writes kd_pid.txt with the pid it spawned).
param([int]$Port = 50035)

$kdps = Get-Process kd -ErrorAction SilentlyContinue
if (-not $kdps) { "NO-KD-PROCESSES" } else {
    foreach ($k in $kdps) {
        $wmi = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $k.Id) -ErrorAction SilentlyContinue
        $parent = $null
        if ($wmi) {
            $parent = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $wmi.ParentProcessId) -ErrorAction SilentlyContinue
        }
        ("KD PID {0} | start {1} | parent {2} ({3})" -f $k.Id, $k.StartTime, $(if ($wmi) { $wmi.ParentProcessId } else { "?" }), $(if ($parent) { $parent.Name } else { "DEAD" }))
        ("  CMDLINE: {0}" -f $(if ($wmi) { $wmi.CommandLine } else { "?" }))
        $eps = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $k.Id }
        if ($eps) {
            $eps | Select-Object LocalAddress, LocalPort | Format-Table -AutoSize | Out-String
        } else {
            "  (no UDP endpoints visible)"
        }
    }
}

$eps = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue
if ($eps) {
    "PORT {0} HELD BY:" -f $Port
    $eps | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        "  {0}  pid={1}  proc={2}" -f $_.LocalAddress, $_.OwningProcess, $(if ($p) { $p.ProcessName } else { "?" })
    }
} else {
    "PORT {0} FREE" -f $Port
}
