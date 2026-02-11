$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CacheDir = if ($env:FAST_COMPLETER_CACHE) { $env:FAST_COMPLETER_CACHE } else { "$env:LOCALAPPDATA\fast-completer" }
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
Copy-Item "$ScriptDir\blobs\*.fcmpb" -Destination $CacheDir
Write-Host "Installed blobs to $CacheDir"
