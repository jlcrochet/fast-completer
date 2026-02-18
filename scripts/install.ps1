$ErrorActionPreference = "Stop"

$githubRepo = "jlcrochet/fast-completer"
$onWindows = $env:OS -eq "Windows_NT"
$addPath = $env:FC_ADD_PATH -eq "1"
$menuComplete = $env:FC_MENU_COMPLETE -eq "1"
$onlyBlobs = if ($env:FC_ONLY) { $env:FC_ONLY -split "," | ForEach-Object { $_.Trim() } } else { @() }
$excludeBlobs = if ($env:FC_EXCLUDE) { $env:FC_EXCLUDE -split "," | ForEach-Object { $_.Trim() } } else { @() }
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

    $blobSrc = Join-Path $extractDir "blobs"
    if ($onlyBlobs.Count -gt 0) {
        foreach ($name in $onlyBlobs) {
            $blob = Join-Path $blobSrc "$name.fcmpb"
            if (Test-Path $blob) {
                Copy-Item $blob -Destination $cache
            } else {
                Write-Warning "Blob not found: $name.fcmpb"
            }
        }
    } elseif ($excludeBlobs.Count -gt 0) {
        foreach ($blob in Get-ChildItem "$blobSrc/*.fcmpb") {
            if ($blob.BaseName -notin $excludeBlobs) {
                Copy-Item $blob.FullName -Destination $cache
            }
        }
    } else {
        Copy-Item -Path "$blobSrc/*.fcmpb" -Destination $cache
    }
    Write-Host "Installed blobs to $cache"

    # Add to PATH
    if ($addPath) {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -split ";" | Where-Object { $_ -eq $dest }) {
            Write-Host "$dest is already in PATH"
        } else {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$dest", "User")
            $env:PATH += [System.IO.Path]::PathSeparator + $dest
            Write-Host "Added $dest to PATH"
        }
    }

    # Set up PowerShell profile
    $marker = "# fast-completer shell completions"
    $menuMarker = "# fast-completer MenuComplete"
    $profilePath = $PROFILE.CurrentUserCurrentHost
    New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null

    # Completions
    $needsCompletions = (-not (Test-Path $profilePath)) -or (-not (Select-String -Quiet -SimpleMatch $marker -Path $profilePath))
    if ($needsCompletions) {
        $completionBlock = @"

$marker
`$fcCompleter = {
    param(`$wordToComplete, `$commandAst, `$cursorPosition)
    `$spans = @(`$commandAst.CommandElements | ForEach-Object { `$_.Extent.Text })
    if (`$cursorPosition -gt `$commandAst.CommandElements[-1].Extent.EndOffset) { `$spans += ' ' }
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
        Add-Content -Path $profilePath -Value $completionBlock
        Write-Host "Added shell completions to $profilePath"
    } else {
        Write-Host "Shell completions already configured in $profilePath"
    }

    # MenuComplete
    if ($menuComplete) {
        $hasMenu = (Test-Path $profilePath) -and (Select-String -Quiet -SimpleMatch $menuMarker -Path $profilePath)
        if (-not $hasMenu) {
            Add-Content -Path $profilePath -Value "`n$menuMarker`nSet-PSReadLineKeyHandler -Key Tab -Function MenuComplete"
            Write-Host "Added MenuComplete to $profilePath"
        } else {
            Write-Host "MenuComplete already configured in $profilePath"
        }
    }

    # Source profile to activate everything in current session
    . $profilePath
    Write-Host ""
    Write-Host "Done! Completions are active in this session."
    Write-Host "  Binary: $dest/$binary"
    Write-Host "  Blobs: $cache"
    Write-Host "  Profile: $profilePath"
    if (-not $addPath -and -not ($env:PATH -split [System.IO.Path]::PathSeparator | Where-Object { $_ -eq $dest })) {
        Write-Host ""
        Write-Host "To add $dest to your PATH permanently, run:"
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';$dest', 'User')"
        Write-Host "Or re-run with: `$env:FC_ADD_PATH=1"
    }
    if (-not $menuComplete -and -not $listView) {
        Write-Host ""
        Write-Host "For interactive menu-style completions, re-run with:"
        Write-Host "  `$env:FC_MENU_COMPLETE=1"
    }
} finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
