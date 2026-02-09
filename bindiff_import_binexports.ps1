param(
    [Parameter(Mandatory=$true)]
    [string]$DiffsDir,
    
    [Parameter(Mandatory=$false)]
    [string]$BinDiffPath = "C:\Program Files\BinDiff\bin\bindiff.exe"
)

if (-not (Test-Path $BinDiffPath)) {
    Write-Error "BinDiff not found at: $BinDiffPath"
    Write-Host "Please specify the correct path using -BinDiffPath parameter"
    exit 1
}

if (-not (Test-Path $DiffsDir)) {
    Write-Error "Diffs directory not found: $DiffsDir"
    exit 1
}

Write-Host "Processing BinExport files in: $DiffsDir" -ForegroundColor Cyan
Write-Host ""

# Find all PE directories with both patched and unpatched BinExport files
$peDirs = Get-ChildItem -Path $DiffsDir -Directory

$pairs = @()

foreach ($peDir in $peDirs) {
    $peName = $peDir.Name
    $patchedFile = Join-Path $peDir.FullName "patched_$peName.BinExport"
    $unpatchedFile = Join-Path $peDir.FullName "unpatched_$peName.BinExport"
    
    if ((Test-Path $patchedFile) -and (Test-Path $unpatchedFile)) {
        $pairs += @{
            Name = $peName
            Directory = $peDir.FullName
            Patched = $patchedFile
            Unpatched = $unpatchedFile
        }
        Write-Host "Found pair: $peName" -ForegroundColor Green
    } else {
        Write-Host "Incomplete pair: $peName (missing patched or unpatched)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Found $($pairs.Count) complete BinExport pairs" -ForegroundColor Cyan
Write-Host ""

if ($pairs.Count -eq 0) {
    Write-Error "No valid BinExport pairs found in $DiffsDir"
    exit 1
}

# Diff each pair - output to the same directory
$successCount = 0
$failCount = 0
$results = @()

foreach ($pair in $pairs) {
    Write-Host "Diffing: $($pair.Name)" -ForegroundColor Yellow
    
    # BinDiff command - output to the binary's own directory
    $cmd = @(
        "--primary=`"$($pair.Unpatched)`"",
        "--secondary=`"$($pair.Patched)`"",
        "--output_dir=`"$($pair.Directory)`""
    )
    
    $output = & $BinDiffPath @cmd 2>&1
    
    $result = @{
        Name = $pair.Name
        Directory = $pair.Directory
        ExitCode = $LASTEXITCODE
        Success = ($LASTEXITCODE -eq 0)
    }
    
    $results += $result
    
    if ($result.Success) {
        Write-Host "Success: $($pair.Name) -> $($pair.Directory)" -ForegroundColor Green
        $successCount++
    } else {
        Write-Host "Failed: $($pair.Name)" -ForegroundColor Red
        Write-Host "Error: $output" -ForegroundColor Red
        $failCount++
    }
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BinDiff Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total pairs: $($pairs.Count)" -ForegroundColor White
Write-Host "Success: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "Failed diffs:" -ForegroundColor Red
    $results | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Host "  - $($_.Name) (Exit code: $($_.ExitCode))" -ForegroundColor Red
    }
}