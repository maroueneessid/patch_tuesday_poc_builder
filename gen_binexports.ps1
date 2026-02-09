param(
    [Parameter(Mandatory=$true)]
    [string]$TargetDir,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("patched", "unpatched")]
    [string]$Type
)

$ghidraHeadless = "C:\MyProgs\Ghidra\ghidra_11.0.3_PUBLIC\support\analyzeHeadless.bat"
$projectBase = "C:\MyProgs\Ghidra\Projects\CVE-2026-20843"
$scriptPath = "C:\MyProgs\Ghidra\Scripts"
$scriptName = "binExport.py"
$timeout = 300

if (-not (Test-Path $TargetDir)) {
    Write-Error "Directory not found: $TargetDir"
    exit 1
}

# Find all .dll and .exe files in subdirectories
$binaries = Get-ChildItem -Path $TargetDir -Include "*.dll", "*.exe" -Recurse -File

Write-Host "Found $($binaries.Count) binaries to process in $TargetDir" -ForegroundColor Cyan
Write-Host ""

$results = @()

foreach ($binary in $binaries) {
    Write-Host "Processing: $($binary.FullName)" -ForegroundColor Yellow
    
    $cmd = @(
        "`"$projectBase`"",
        "`"$Type`"",
        "-import",
        "`"$($binary.FullName)`"",
        "-analysisTimeoutPerFile",
        "$timeout",
        "-scriptPath",
        "$scriptPath",
        "-postScript",
        "`"$scriptName`""
    )
    
    & $ghidraHeadless @cmd
    
    $result = @{
        Binary = $binary.Name
        FullPath = $binary.FullName
        ExitCode = $LASTEXITCODE
        Success = ($LASTEXITCODE -eq 0)
    }
    
    $results += $result
    
    if ($result.Success) {
        Write-Host "Success: $($binary.Name)" -ForegroundColor Green
    } else {
        Write-Host "Failed: $($binary.Name) (Exit code: $LASTEXITCODE)" -ForegroundColor Red
    }
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Processing Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$successCount = ($results | Where-Object { $_.Success }).Count
$failCount = ($results | Where-Object { -not $_.Success }).Count

Write-Host "Total: $($results.Count)" -ForegroundColor White
Write-Host "Success: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "Failed binaries:" -ForegroundColor Red
    $results | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Host "  - $($_.Binary) (Exit code: $($_.ExitCode))" -ForegroundColor Red
    }
}