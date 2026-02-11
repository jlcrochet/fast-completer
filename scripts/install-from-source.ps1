$ErrorActionPreference = "Stop"

$generateArgs = if ($env:FC_GENERATE_OPTS) { $env:FC_GENERATE_OPTS -split ' ' } else { @() }
$repo = "https://github.com/jlcrochet/fast-completer.git"
$tmp = Join-Path $env:TEMP "fast-completer-install"

if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }

try {
    Write-Host "Cloning fast-completer..."
    git clone --depth 1 $repo $tmp

    Write-Host "Building..."
    Push-Location $tmp
    cl /O2 /DNDEBUG /Fe:fast-completer.exe src\fast-completer.c src\generate_blob.c src\compat\getopt.c
    Pop-Location

    $dest = "$env:LOCALAPPDATA\Programs"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item "$tmp\fast-completer.exe" $dest
    Write-Host "Installed binary to $dest\fast-completer.exe"

    Write-Host "Generating blobs..."
    Get-ChildItem "$tmp\schemas\*\*.fcmps" | ForEach-Object {
        & "$tmp\fast-completer.exe" --generate-blob @generateArgs $_
    }

    $cache = if ($env:FAST_COMPLETER_CACHE) { $env:FAST_COMPLETER_CACHE } else { "$env:LOCALAPPDATA\fast-completer" }
    Write-Host "Done! Blobs installed to $cache\"
    if (-not ($env:Path -split ";" | Where-Object { $_ -eq $dest })) {
        Write-Host "NOTE: Add $dest to your PATH if not already present."
    }
} finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
