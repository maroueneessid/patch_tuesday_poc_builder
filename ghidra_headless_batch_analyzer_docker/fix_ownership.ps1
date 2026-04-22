#!/usr/bin/env pwsh
# Fix Ghidra project ownership in .rep/project.prp files.
# Usage: .\fix_ownership.ps1 <ghidra_projects_dir> [username]
# If username is omitted, defaults to current user.

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProjectDir,

    [Parameter(Position=1)]
    [string]$Username = $env:USERNAME
)

if (-not (Test-Path $ProjectDir -PathType Container)) {
    Write-Error "Not a directory: $ProjectDir"
    exit 1
}

$prpFiles = Get-ChildItem -Path $ProjectDir -Recurse -Filter "project.prp"

if ($prpFiles.Count -eq 0) {
    Write-Host "No project.prp files found in $ProjectDir"
    exit 0
}

foreach ($prp in $prpFiles) {
    $content = Get-Content -Path $prp.FullName -Raw
    $patched = $content -replace 'NAME="OWNER" TYPE="string" VALUE="[^"]*"', "NAME=`"OWNER`" TYPE=`"string`" VALUE=`"$Username`""
    Set-Content -Path $prp.FullName -Value $patched -NoNewline
    Write-Host "Patched: $($prp.FullName) -> OWNER=$Username"
}
