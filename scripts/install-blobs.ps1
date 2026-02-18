param(
    [string[]]$Only,
    [string[]]$Exclude
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CacheDir = if ($env:FAST_COMPLETER_CACHE) { $env:FAST_COMPLETER_CACHE } else { "$env:LOCALAPPDATA\fast-completer" }
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null

$src = Join-Path $ScriptDir "blobs"
$count = 0

if ($Only) {
    foreach ($name in $Only) {
        $blob = Join-Path $src "$name.fcmpb"
        if (Test-Path $blob) {
            Copy-Item $blob -Destination $CacheDir
            $count++
        } else {
            Write-Warning "Blob not found: $name.fcmpb"
        }
    }
} elseif ($Exclude) {
    foreach ($blob in Get-ChildItem "$src\*.fcmpb") {
        if ($blob.BaseName -notin $Exclude) {
            Copy-Item $blob.FullName -Destination $CacheDir
            $count++
        }
    }
} else {
    $blobs = Get-ChildItem "$src\*.fcmpb"
    Copy-Item $blobs.FullName -Destination $CacheDir
    $count = $blobs.Count
}

Write-Host "Installed $count blob(s) to $CacheDir"
