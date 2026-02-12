$ErrorActionPreference = "Stop"

$githubRepo = "jlcrochet/fast-completer"
$onWindows = $env:OS -eq "Windows_NT"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "fast-completer-install"

# Detect platform
if ($onWindows) {
    $artifact = "fast-completer-windows-x86_64"
    $binary = "fast-completer.exe"
} else {
    $arch = uname -m
    $os = uname -s
    switch ("$os-$arch") {
        "Linux-x86_64"  { $artifact = "fast-completer-linux-x86_64" }
        "Darwin-arm64"  { $artifact = "fast-completer-macos-arm64" }
        "Darwin-x86_64" { $artifact = "fast-completer-macos-x86_64" }
        default { Write-Error "Unsupported platform: $os $arch"; exit 1 }
    }
    $binary = "fast-completer"
}

$url = "https://github.com/$githubRepo/releases/latest/download/$artifact.zip"

if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }

try {
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    Write-Host "Downloading $artifact.zip..."
    $zipPath = Join-Path $tmp "release.zip"
    Invoke-RestMethod -Uri $url -OutFile $zipPath

    Write-Host "Extracting..."
    $extractDir = Join-Path $tmp "release"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir

    # Install binary
    $dest = if ($onWindows) { "$env:LOCALAPPDATA\Programs" } else { "$HOME/.local/bin" }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item (Join-Path $extractDir $binary) $dest
    Write-Host "Installed binary to $dest/$binary"

    # Install blobs
    $cache = if ($env:FAST_COMPLETER_CACHE) {
        $env:FAST_COMPLETER_CACHE
    } elseif ($onWindows) {
        "$env:LOCALAPPDATA\fast-completer"
    } else {
        "$HOME/.cache/fast-completer"
    }
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    Copy-Item (Join-Path $extractDir "blobs" "*.fcmpb") -Destination $cache
    Write-Host "Installed blobs to $cache"

    # Set up PowerShell completions
    $marker = "# fast-completer shell completions"
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $needsSetup = (-not (Test-Path $profilePath)) -or (-not (Select-String -Quiet -SimpleMatch $marker -Path $profilePath))
    if ($needsSetup) {
        $completionBlock = @"

$marker
`$fcCompleter = {
    param(`$wordToComplete, `$commandAst, `$cursorPosition)
    `$spans = `$commandAst.CommandElements | ForEach-Object { `$_.Extent.Text }
    `$results = fast-completer -q pwsh @spans
    `$results | ForEach-Object {
        `$parts = `$_ -split "``t"
        [System.Management.Automation.CompletionResult]::new(`$parts[0], `$parts[1], `$parts[2], `$parts[3])
    }
}
`$fcCache = if (`$env:FAST_COMPLETER_CACHE) { `$env:FAST_COMPLETER_CACHE } elseif (`$env:LOCALAPPDATA) { "`$env:LOCALAPPDATA\fast-completer" } else { "`$HOME/.cache/fast-completer" }
Get-ChildItem "`$fcCache/*.fcmpb" -ErrorAction SilentlyContinue | ForEach-Object {
    Register-ArgumentCompleter -Native -CommandName `$_.BaseName -ScriptBlock `$fcCompleter
}
"@
        New-Item -ItemType File -Force -Path $profilePath | Out-Null
        Add-Content -Path $profilePath -Value $completionBlock
        Write-Host "Added shell completions to $profilePath"
    } else {
        Write-Host "Shell completions already configured in $profilePath"
    }

    Write-Host ""
    Write-Host "Done!"
    Write-Host "  Binary installed to $dest/$binary"
    Write-Host "  Blobs installed to $cache"
    Write-Host "  Shell completions configured in $profilePath"
    Write-Host ""
    Write-Host "To activate completions in your current session, run:"
    Write-Host "  . $profilePath"
    if (-not ($env:PATH -split [System.IO.Path]::PathSeparator | Where-Object { $_ -eq $dest })) {
        Write-Host ""
        Write-Host "NOTE: Add $dest to your PATH if not already present."
    }
} finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
