$SymChk = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe"
$SourceDir = "C:\Windows\System32"
$BaseOutDir = "C:\diff"
$SymbolCache = "C:\diff\_symcache"
$SymbolServer = "https://msdl.microsoft.com/download/symbols"

$Dlls = @(
    "rascustom.dll", "rasmans.dll", "iprtprio.dll", "iprtrmgr.dll",
    "mprdim.dll", "RasMigPlugin.dll", "rtm.dll", "rastlsext.dll",
    "RasMediaManager.dll", "prxyqry.dll", "rasapi32.dll", "rastls.dll"
)

# CHANGE THIS TO SEARCH DEEPER INTO SYSTEM32 FOR THE DLL
$dllSearchDepth = 2

# Ensure base directories exist
New-Item -ItemType Directory -Path $SymbolCache -Force | Out-Null
if (-not (Test-Path $BaseOutDir)) { New-Item -ItemType Directory -Path $BaseOutDir -Force | Out-Null }

foreach ($dll in $Dlls) {
    Write-Host "`n--- Searching for $dll ---" -ForegroundColor Cyan
    
    # 1. Recursive search for the DLL
    $foundFiles = Get-ChildItem -Path $SourceDir -Filter $dll -Recurse -Depth $dllSearchDepth -File -ErrorAction SilentlyContinue

    if ($foundFiles.Count -eq 0) {
        Write-Warning "DLL not found anywhere in $SourceDir : $dll"
        continue
    }

    $dllPath = ""

    # 2. Hash Validation for multiple findings
    if ($foundFiles.Count -gt 1) {
        $hashes = $foundFiles | Get-FileHash -Algorithm SHA256
        $uniqueHashes = $hashes.Hash | Select-Object -Unique

        if ($uniqueHashes.Count -eq 1) {
            Write-Host "Multiple copies found, but hashes match. Using: $($foundFiles[0].FullName)" -ForegroundColor Gray
            $dllPath = $foundFiles[0].FullName
        } else {
            Write-Error "CRITICAL: Multiple versions of $dll found with DIFFERENT hashes!"
            $hashes | ForEach-Object { Write-Host "  -> Hash: $($_.Hash) Path: $($_.Path)" -ForegroundColor Yellow }
            Write-Warning "Skipping $dll due to version ambiguity."
            continue
        }
    } else {
        $dllPath = $foundFiles.FullName
        Write-Host "Found at: $dllPath" -ForegroundColor Gray
    }

    # 3. Setup Output Directory
    $dllName = [System.IO.Path]::GetFileNameWithoutExtension($dll)
    $outDir = Join-Path $BaseOutDir $dllName
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    # 4. Copy DLL to output
    Copy-Item $dllPath $outDir -Force

    # 5. Download symbols into cache
    Write-Host "Fetching symbols for $dll..."
    & "$SymChk" "$dllPath" /s "SRV*$SymbolCache*$SymbolServer" | Out-Null

    # 6. Find matching PDB in cache and copy to output
    $pdbName = "$dllName.pdb"
    $pdb = Get-ChildItem -Path $SymbolCache -Recurse -Filter $pdbName -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1

    if ($pdb) {
        Copy-Item $pdb.FullName $outDir -Force
        Write-Host "Success: $dll and PDB staged in $outDir" -ForegroundColor Green
    } else {
        Write-Warning "No public PDB found for $dll"
    }
}