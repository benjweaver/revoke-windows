# Installs the latest Revoke release for your user, with no admin rights. It goes in
# %LOCALAPPDATA%\Programs\Revoke, with a Start menu shortcut, and starts in the
# notification area.
#
#   irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/install.ps1 | iex
#
# update.ps1 and uninstall.ps1 beside it run this with -Update or -Uninstall.
# Updating does nothing but make sure Revoke is running when the latest release is
# already installed, and refuses when Revoke isn't installed. Uninstalling also removes
# the admin helper, if it's installed, which asks for admin once; it keeps your settings.
#
# Written for Windows PowerShell 5.1, which every Windows 10 and 11 has.

param([switch]$Uninstall, [switch]$Update)

# Everything runs inside a script block so that `irm | iex` leaves nothing behind
# in your session, and a failure throws rather than closing your terminal.
& {
    param([bool]$Uninstall, [bool]$Update)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # the progress bar slows downloads right down
    $repo = 'benjweaver/revoke-windows'
    $dir = Join-Path $env:LOCALAPPDATA 'Programs\Revoke'
    $exe = Join-Path $dir 'Revoke.exe'
    $shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'Revoke.lnk'
    $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

    # Only Revoke itself, never the apps it watches.
    function Stop-Revoke {
        $running = @(Get-Process Revoke -ErrorAction SilentlyContinue)
        if ($running) {
            $running | Stop-Process -Force
            $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        }
    }

    if ($Uninstall) {
        Stop-Revoke
        # The helper runs as SYSTEM, so removing it asks for admin. Removing it also
        # switches back on the firewall rules it switched off and deletes Revoke's own.
        if (Get-Service RevokeHelper -ErrorAction SilentlyContinue) {
            $helper = Join-Path $dir 'Helper\RevokeHelper.exe'
            if (-not (Test-Path $helper)) { throw "The admin helper is installed but $helper is missing, so it can't be removed." }
            Write-Host 'Removing the admin helper: Windows asks for admin.'
            $p = Start-Process $helper -ArgumentList '--uninstall' -Verb RunAs -WindowStyle Hidden -Wait -PassThru
            if ($p.ExitCode -ne 0) { Write-Warning "Removing the admin helper didn't finish (exit code $($p.ExitCode))." }
        }
        Remove-ItemProperty $run -Name Revoke -ErrorAction SilentlyContinue
        Remove-Item $shortcut -Force -ErrorAction SilentlyContinue
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Revoke is removed. Your settings in $env:APPDATA\Revoke are still there."
        return
    }
    if ($Update -and -not (Test-Path $exe)) {
        throw "Revoke isn't installed in $dir. Install it with: irm https://raw.githubusercontent.com/$repo/main/packaging/windows/install.ps1 | iex"
    }

    # PROCESSOR_ARCHITEW6432 is set when a 32-bit PowerShell runs on 64-bit Windows.
    # ARM64 Windows 11 runs the x64 build through its emulation.
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -notin 'AMD64', 'ARM64') { throw "Revoke has no build for $arch Windows" }
    $flavour = 'windows-x64'

    # Windows PowerShell 5.1 doesn't offer TLS 1.2 on its own, and GitHub needs it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # While the repository is private, GitHub only answers someone signed in, so this
    # falls back to the GitHub CLI when it's installed and signed in.
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
        $viaGh = $false
    }
    catch {
        if (-not $gh) { throw "Couldn't find Revoke's latest release on GitHub: $($_.Exception.Message)" }
        $release = gh api "repos/$repo/releases/latest" | ConvertFrom-Json
        if (-not $release) { throw "Couldn't find Revoke's latest release on GitHub, even signed in with gh." }
        $viaGh = $true
    }
    $tag = $release.tag_name
    $version = $tag.TrimStart('v')

    if (Test-Path $exe) {
        # The product version carries the commit after a +, which isn't part of the release number.
        $current = ((Get-Item $exe).VersionInfo.ProductVersion -split '\+')[0]
        if ($current -eq $version) {
            Write-Host "Revoke $current is already the latest release."
            if (-not (Get-Process Revoke -ErrorAction SilentlyContinue)) { Start-Process $exe -ArgumentList '--background' }
            return
        }
        Write-Host "Updating Revoke $current to $version"
    }
    $zipName = "Revoke-$version-$flavour.zip"

    $work = Join-Path ([IO.Path]::GetTempPath()) "revoke-install-$([guid]::NewGuid())"
    New-Item -ItemType Directory $work | Out-Null
    try {
        Write-Host "Downloading Revoke $version"
        $zip = Join-Path $work $zipName
        $sums = Join-Path $work 'SHA256SUMS'
        if ($viaGh) {
            gh release download $tag --repo $repo --pattern $zipName --pattern SHA256SUMS --dir $work
            if ($LASTEXITCODE -ne 0) { throw "gh couldn't download $zipName" }
        }
        else {
            $base = "https://github.com/$repo/releases/download/$tag"
            Invoke-WebRequest "$base/$zipName" -OutFile $zip -UseBasicParsing
            Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
        }
        # The file lists "<hash>  <name>", one per line.
        $line = Get-Content $sums | Where-Object { $_ -match "\s\*?$([regex]::Escape($zipName))\s*$" } | Select-Object -First 1
        if (-not $line) { throw "SHA256SUMS for $tag doesn't list $zipName" }
        $expected = ($line -split '\s+')[0]
        $actual = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($actual -ne $expected) { throw "$zipName doesn't match its checksum; nothing was installed" }

        # The zip holds a single folder named Revoke.
        Expand-Archive $zip -DestinationPath $work
        $new = Join-Path $work 'Revoke'
        Get-ChildItem $new -Recurse -File | Unblock-File

        Stop-Revoke
        New-Item -ItemType Directory $dir -Force | Out-Null
        # /MIR makes the folder match the release exactly, so files a newer one dropped go too.
        robocopy $new $dir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Copying Revoke into $dir failed (robocopy exit code $LASTEXITCODE)" }
        Write-Host "Installed Revoke in $dir"
    }
    finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    $link = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut)
    $link.TargetPath = $exe
    $link.WorkingDirectory = $dir
    $link.IconLocation = "$exe,0"
    $link.Description = 'Shows and revokes what AI agents can do on this PC'
    $link.Save()

    # Keep "Open at sign-in" as it was, pointed here.
    if ((Get-ItemProperty $run -ErrorAction SilentlyContinue).Revoke) {
        Set-ItemProperty $run -Name Revoke -Value "`"$exe`" --background"
    }

    # The first time, Revoke opens its settings by itself.
    Start-Process $exe
    Write-Host 'Revoke is running. Find it in the notification area, or Start > Revoke.'

    $installed = Join-Path $env:ProgramFiles 'Revoke\Helper\RevokeHelper.exe'
    $bundled = Join-Path $dir 'Helper\RevokeHelper.exe'
    if ((Test-Path $installed) -and (Get-FileHash $installed).Hash -ne (Get-FileHash $bundled).Hash) {
        Write-Host 'This release has a newer admin helper: Revoke Settings > General > Admin helper > Update.'
    }
} $Uninstall.IsPresent $Update.IsPresent
