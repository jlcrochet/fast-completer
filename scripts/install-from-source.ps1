$ErrorActionPreference = "Stop"

$generateArgs = if ($env:FC_GENERATE_OPTS) { $env:FC_GENERATE_OPTS -split ' ' } else { @() }
$onWindows = $env:OS -eq "Windows_NT"
$repo = "https://github.com/jlcrochet/fast-completer.git"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "fast-completer-install"

if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }

try {
    Write-Host "Cloning fast-completer..."
    git clone --depth 1 $repo $tmp

    Write-Host "Building..."
    if ($onWindows) {
        Push-Location $tmp
        cl /O2 /DNDEBUG /Fe:fast-completer.exe src\fast-completer.c src\generate_blob.c src\compat\getopt.c
        Pop-Location
    } else {
        make -C $tmp
    }

    $binary = if ($onWindows) { "fast-completer.exe" } else { "fast-completer" }
    $dest = if ($onWindows) { "$env:LOCALAPPDATA\Programs" } else { "$HOME/.local/bin" }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item (Join-Path $tmp $binary) $dest
    Write-Host "Installed binary to $dest/$binary"

    Write-Host "Generating blobs..."
    Get-ChildItem "$tmp/schemas/*/*.fcmps" | ForEach-Object {
        & (Join-Path $tmp $binary) --generate-blob @generateArgs $_
    }

    $cache = if ($env:FAST_COMPLETER_CACHE) {
        $env:FAST_COMPLETER_CACHE
    } elseif ($onWindows) {
        "$env:LOCALAPPDATA\fast-completer"
    } else {
        "$HOME/.cache/fast-completer"
    }
    Write-Host "Done! Blobs installed to $cache"
    if (-not ($env:PATH -split [System.IO.Path]::PathSeparator | Where-Object { $_ -eq $dest })) {
        Write-Host "NOTE: Add $dest to your PATH if not already present."
    }
} finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
