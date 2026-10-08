# Builds Revoke from this checkout and installs it for your user, with no admin rights.
# It goes in %LOCALAPPDATA%\Programs\Revoke, with a Start menu shortcut, and starts.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#
# A Revoke already running is stopped first, and only Revoke: apps it watches are
# left alone. Your settings, in %APPDATA%\Revoke, stay. If "Open at sign-in" is on,
# it's pointed at the installed copy. The admin helper service is installed from
# Revoke's settings, which offer Update when this build brings a newer one.
#
# Written for Windows PowerShell 5.1, which every Windows 10 and 11 has.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $env:LOCALAPPDATA 'Programs\Revoke'
$exe = Join-Path $dir 'Revoke.exe'
$publish = Join-Path $repo 'publish'

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet)) { throw 'Building Revoke needs the .NET 10 SDK: winget install Microsoft.DotNet.SDK.10' }

Write-Host 'Building a release...'
Remove-Item $publish -Recurse -Force -ErrorAction SilentlyContinue
& $dotnet publish (Join-Path $repo 'src\Revoke') -c Release -o $publish --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw "The build failed (exit code $LASTEXITCODE)." }
if (-not (Test-Path (Join-Path $publish 'Helper\RevokeHelper.exe'))) { throw 'The build has no helper in it.' }

# Only Revoke itself, matched by path or name, never what it watches.
$running = @(Get-Process Revoke -ErrorAction SilentlyContinue)
if ($running) {
    Write-Host 'Stopping the Revoke that is running...'
    $running | Stop-Process -Force
    $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}

Write-Host "Installing in $dir..."
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# /MIR makes the folder match the build exactly, so files a newer build dropped go too.
robocopy $publish $dir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying the build failed (robocopy exit code $LASTEXITCODE)." }
# Below 8, robocopy is saying what it copied, not failing; don't pass that on as an exit code.
$global:LASTEXITCODE = 0
Remove-Item $publish -Recurse -Force -ErrorAction SilentlyContinue

$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'Revoke.lnk'
$link = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut)
$link.TargetPath = $exe
$link.WorkingDirectory = $dir
$link.IconLocation = "$exe,0"
$link.Description = 'Shows and revokes what AI agents can do on this PC'
$link.Save()

# Keep "Open at sign-in" as it was, pointed here.
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if ((Get-ItemProperty $run -ErrorAction SilentlyContinue).Revoke) {
    Set-ItemProperty $run -Name Revoke -Value "`"$exe`" --background"
}

# Through Explorer, so Revoke starts as if you'd opened it, even from a terminal inside
# another app's container (Claude Code's or Codex's, say).
Start-Process explorer.exe -ArgumentList "`"$exe`""
$version = (Get-Item $exe).VersionInfo.ProductVersion
Write-Host "Revoke $version is installed and running. Find it in the notification area, or Start > Revoke."

$installed = Join-Path $env:ProgramFiles 'Revoke\Helper\RevokeHelper.exe'
$bundled = Join-Path $dir 'Helper\RevokeHelper.exe'
if (Test-Path $installed) {
    $a = Get-Item $installed; $b = Get-Item $bundled
    if ($a.Length -ne $b.Length -or $a.LastWriteTimeUtc -ne $b.LastWriteTimeUtc) {
        Write-Host 'This build has a newer admin helper: Revoke Settings > General > Admin helper > Update.'
    }
}
