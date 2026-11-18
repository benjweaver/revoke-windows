# Runs in the signed-in Windows VM desktop. scripts/vm-test.ps1 stages and starts it.
# All fixture processes and switch changes are undone even when a check fails.
param(
    [Parameter(Mandatory)][string]$Stage,
    [Parameter(Mandatory)][string]$Output
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$report = [ordered]@{ started = (Get-Date).ToString('o'); session = (Get-Process -Id $PID).SessionId; checks = @(); finished = $null }
$revoke = Join-Path $Stage 'Revoke\Revoke.exe'
$fixture = Join-Path $Stage 'fixtures'
$ag = Join-Path $fixture 'antigravity\app-1.0.0\AntigravityProbe.exe'
$agNew = Join-Path $fixture 'antigravity\app-1.0.1\AntigravityProbe.exe'
$vs = Join-Path $fixture 'vscodium\app-1.0.0\VSCodiumProbe.exe'
$held = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$changed = New-Object System.Collections.Generic.List[string]
$appStarted = $false
$originalTheme = $null
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$progressFile = Join-Path $Output 'progress.log'
function Mark([string]$step) { Add-Content $progressFile "$(Get-Date -Format o) $step" }
Mark 'started'

function Record([string]$name, [string]$status, [string]$detail = '') {
    $script:report.checks += [ordered]@{ name = $name; status = $status; detail = $detail }
}
function Check([string]$name, [scriptblock]$body) {
    Mark "checking $name"
    try { & $body; Record $name 'pass'; Mark "passed $name" }
    catch { Record $name 'fail' $_.Exception.Message; Mark "failed $name`: $($_.Exception.Message)"; throw }
}
function Wait-For([scriptblock]$condition, [int]$seconds = 30) {
    $until = (Get-Date).AddSeconds($seconds)
    do {
        $value = & $condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $until)
    throw "Timed out after $seconds seconds."
}
function Find-Ui([string]$name) {
    $condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, $name)
    return [Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
}
function Get-Ui([string]$name, [int]$seconds = 30) {
    return Wait-For { Find-Ui $name } $seconds
}
function Invoke-Ui([string]$name) {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            $element = Get-Ui $name
            $pattern = $element.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)
            $pattern.Invoke()
            return
        } catch {
            if ($attempt -eq 2) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}
function Set-Switch([string]$name, [bool]$on) {
    $want = if ($on) { [Windows.Automation.ToggleState]::On } else { [Windows.Automation.ToggleState]::Off }
    if ((Known-BackendState $name) -and (BackendMatches $name $on)) { return }
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try {
            if (-not (Find-Ui $name)) { Show-Panel }
            $element = Wait-For {
                try {
                    $candidate = Find-Ui $name
                    if ($candidate -and $candidate.Current.IsEnabled) { return $candidate }
                } catch { }
                return $null
            } 30
            $pattern = $element.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
            if ($pattern.Current.ToggleState -ne $want) { $pattern.Toggle() }
            if (Known-BackendState $name) {
                Wait-For { BackendMatches $name $on } 60 | Out-Null
            } else {
                Wait-For {
                    $fresh = Find-Ui $name
                    if (-not $fresh) { return $false }
                    $toggle = $fresh.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
                    $fresh.Current.IsEnabled -and $toggle.Current.ToggleState -eq $want
                } 60 | Out-Null
            }
            return
        }
        catch {
            if ((Known-BackendState $name) -and (BackendMatches $name $on)) { return }
            if ($attempt -eq 3) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}
function Signal-Instance([string]$eventName) {
    # Signal the running instance from this desktop session without taking focus away.
    $handle = Wait-For {
        $handle = $null
        if ([Threading.EventWaitHandle]::TryOpenExisting($eventName, [ref]$handle)) {
            return $handle
        }
        return $null
    } 45
    try { $handle.Set() | Out-Null }
    finally { $handle.Dispose() }
}
function Show-Panel {
    Signal-Instance 'Local\dev.benjweaver.Revoke.panel'
    Mark 'panel event sent'
    try { Get-Ui 'Internet for antigravityprobe' 45 | Out-Null }
    catch {
        $running = @(Get-Process Revoke -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.SessionId)" }) -join ','
        Mark "panel lookup failed; Revoke processes=$running"
        $windows = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
        $lines = foreach ($window in $windows) {
            if ($window.Current.ProcessId -notin @((Get-Process Revoke -ErrorAction SilentlyContinue).Id)) { continue }
            "Window: $($window.Current.Name)"
            $all = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
            foreach ($item in $all) { if ($item.Current.Name -match 'Internet|Antigravity|VSCodium') { "$($item.Current.ControlType.ProgrammaticName): $($item.Current.Name)" } }
        }
        $lines | Set-Content (Join-Path $Output 'ui-tree.txt')
        throw
    }
}
function Capture([string]$elementName, [string]$file) {
    $element = Get-Ui $elementName
    $walker = [Windows.Automation.TreeWalker]::ControlViewWalker
    while ($element -and ($element.Current.NativeWindowHandle -eq 0 -or $element.Current.ControlType -ne [Windows.Automation.ControlType]::Window)) {
        $element = $walker.GetParent($element)
    }
    if (-not $element) { throw "No window around $elementName." }
    $windowHandle = [IntPtr]$element.Current.NativeWindowHandle
    $rect = New-Object RevokeVmCapture+Rect
    if (-not [RevokeVmCapture]::GetWindowRect($windowHandle, [ref]$rect)) { throw 'Could not get window bounds.' }
    $originalX = $rect.Left
    $originalY = $rect.Top
    # Keep the screenshot clear of desktop overlays at the bottom of the VM screen.
    if (-not [RevokeVmCapture]::SetWindowPos($windowHandle, [IntPtr]::Zero, 16, 16, 0, 0, 0x15)) { throw 'Could not move the window for a screenshot.' }
    try {
        Start-Sleep -Milliseconds 300
        if (-not [RevokeVmCapture]::GetWindowRect($windowHandle, [ref]$rect)) { throw 'Could not get moved window bounds.' }
        $width = $rect.Right - $rect.Left
        $height = $rect.Bottom - $rect.Top
        if ($width -lt 100 -or $height -lt 100) { throw "Unexpected screenshot bounds: ${width}x${height}." }
        $bitmap = New-Object System.Drawing.Bitmap($width, $height)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
                $bitmap.Save((Join-Path $Output $file), [System.Drawing.Imaging.ImageFormat]::Png)
            } finally { $graphics.Dispose() }
        } finally { $bitmap.Dispose() }
    } finally {
        [RevokeVmCapture]::SetWindowPos($windowHandle, [IntPtr]::Zero, $originalX, $originalY, 0, 0, 0x15) | Out-Null
    }
}
function Probe-Tcp([string]$exe, [string]$hostName, [int]$port = 443) {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $result = & $exe tcp $hostName $port
        $code = $LASTEXITCODE
        Mark "tcp ${hostName}:${port} exit=$code result=$($result -join '; ')"
        if ($code -ne 2) { break }
        if ($attempt -lt 2) { Start-Sleep 1 }
    }
    if ($code -eq 2) { throw "Probe DNS failed for ${hostName}: ${result}" }
    return $code -eq 0
}
function Has-InternetRule([string]$program) {
    $rules = @(Get-NetFirewallRule -DisplayGroup 'Revoke' -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.DisplayName -like '*internet*' })
    $protocols = @($rules | Where-Object {
        $filter = $_ | Get-NetFirewallApplicationFilter
        $filter.Program -eq $program
    } | ForEach-Object { ($_ | Get-NetFirewallPortFilter).Protocol })
    return ('TCP' -in $protocols -and 'UDP' -in $protocols) -or (6 -in $protocols -and 17 -in $protocols)
}
function Has-LocalRule([string]$program) {
    $rules = @(Get-NetFirewallRule -DisplayGroup 'Revoke' -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.DisplayName -like '*local network*' })
    $protocols = @($rules | Where-Object {
        $filter = $_ | Get-NetFirewallApplicationFilter
        $filter.Program -eq $program
    } | ForEach-Object { ($_ | Get-NetFirewallPortFilter).Protocol })
    return ('TCP' -in $protocols -and 'UDP' -in $protocols) -or (6 -in $protocols -and 17 -in $protocols)
}
function Needs-Restore([string]$name) {
    switch ($name) {
        'Internet for antigravityprobe' { return (Has-InternetRule $ag) }
        'Internet for vscodiumprobe' { return (Has-InternetRule $vs) }
        'Local network for antigravityprobe' { return (Has-LocalRule $ag) }
        'Internet for ChatGPT' {
            return @((Get-NetFirewallRule -DisplayGroup Revoke -ErrorAction SilentlyContinue) |
                Where-Object { $_.DisplayName -like '*ChatGPT*internet*' -and $_.Enabled -eq 'True' }).Count -gt 0
        }
    }
    return $true
}
function Known-BackendState([string]$name) {
    return $name -in @('Internet for antigravityprobe', 'Internet for vscodiumprobe',
        'Local network for antigravityprobe', 'Internet for ChatGPT')
}
function BackendMatches([string]$name, [bool]$on) {
    return (Needs-Restore $name) -eq (-not $on)
}

try {
    Mark 'preflight'
    if ($report.session -eq 0) { throw 'The runner is not in the signed-in desktop session.' }
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RevokeVmCapture {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SetWindowPos(IntPtr hwnd, IntPtr insertAfter, int x, int y, int width, int height, uint flags);
}
'@
    $sourceProbe = Join-Path $Stage 'Probe\RevokeVmProbe.exe'
    if (Test-Path $sourceProbe) {
        foreach ($path in @($ag, $vs)) {
            New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
            Copy-Item -LiteralPath $sourceProbe -Destination $path -Force
        }
    }
    foreach ($path in @($revoke, $ag, $vs)) { if (-not (Test-Path $path)) { throw "Missing $path" } }
    $other = @(Get-Process Revoke -ErrorAction SilentlyContinue)
    if ($other.Count -ne 0) { throw 'Revoke was already running in the VM. The suite requires a fresh guest session.' }
    $oldFixtures = @(Get-Process AntigravityProbe,VSCodiumProbe -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($Stage, [StringComparison]::OrdinalIgnoreCase) })
    if ($oldFixtures.Count -ne 0) { throw 'A probe from an earlier VM run is still running.' }
    if (Test-Path $agNew) { Remove-Item -LiteralPath $agNew -Force }
    $oldUpdater = Join-Path (Split-Path $ag) 'Updater.tmp'
    if (Test-Path $oldUpdater) { Remove-Item -LiteralPath $oldUpdater -Force }
    $helper = Join-Path $Stage 'Revoke\Helper\RevokeHelper.exe'
    $installedHelper = Join-Path $env:ProgramFiles 'Revoke\Helper\RevokeHelper.exe'
    if (-not (Test-Path $installedHelper) -or (Get-FileHash $helper).Hash -ne (Get-FileHash $installedHelper).Hash) {
        $helperReport = Join-Path $Output 'helper-update.txt'
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $helper
        $startInfo.Arguments = '--report "' + $helperReport + '" --install ' + $sid
        $startInfo.UseShellExecute = $true
        $startInfo.Verb = 'runas'
        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        Mark 'helper UAC requested'
        # The installer is Revoke's bundled helper; Windows asks the VM user for consent.
        $installer = [System.Diagnostics.Process]::Start($startInfo)
        if (-not $installer -or -not $installer.WaitForExit(180000)) { throw 'The helper Update UAC step timed out.' }
        if ($installer.ExitCode -ne 0) {
            $detail = if (Test-Path $helperReport) { (Get-Content $helperReport -Raw).Trim() } else { '' }
            throw "Helper Update exited $($installer.ExitCode): $detail"
        }
        $installer.Dispose()
        Wait-For {
            (Test-Path $installedHelper) -and
            (Get-FileHash $helper).Hash -eq (Get-FileHash $installedHelper).Hash -and
            (Get-Service RevokeHelper -ErrorAction SilentlyContinue).Status -eq 'Running'
        } 60 | Out-Null
    }
    if ((Get-Service RevokeHelper -ErrorAction SilentlyContinue).Status -ne 'Running') { throw 'RevokeHelper is not running.' }
    Record 'matching admin helper' 'pass'
    Mark 'helper matched'

    $held.Add((Start-Process -FilePath $ag -ArgumentList 'hold' -PassThru))
    $held.Add((Start-Process -FilePath $vs -ArgumentList 'hold' -PassThru))
    Mark 'fixtures started'
    $appProcess = Start-Process -FilePath $revoke -ArgumentList '--background' -PassThru
    $appStarted = $true
    Mark "Revoke started pid=$($appProcess.Id)"
    Show-Panel
    Mark 'panel found'

    Check 'reset fixture network switches' {
        Set-Switch 'Internet for antigravityprobe' $true
        Set-Switch 'Internet for vscodiumprobe' $true
        Set-Switch 'Local network for antigravityprobe' $true
    }
    Check 'baseline public connections' {
        foreach ($test in @(@($ag, 'accounts.google.com'), @($ag, 'example.com'), @($vs, 'example.com'))) {
            try {
                Wait-For {
                    try { Probe-Tcp $test[0] $test[1] }
                    catch { $false }
                } 30 | Out-Null
            } catch { throw "$($test[1]) was unreachable from $($test[0]) before limiting Internet." }
        }
    }
    $gateway = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)[0]
    $lanPort = 0
    if ($gateway) {
        foreach ($port in @(445, 135, 80, 443)) {
            if (Probe-Tcp $ag $gateway $port) { $lanPort = $port; break }
        }
    }

    $themeKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $theme = Get-ItemProperty $themeKey
    $originalTheme = @($theme.AppsUseLightTheme, $theme.SystemUsesLightTheme)
    Check 'panel screenshots' {
        Show-Panel
        Set-ItemProperty $themeKey AppsUseLightTheme 1
        Set-ItemProperty $themeKey SystemUsesLightTheme 1
        Start-Sleep 2
        Capture 'Internet for antigravityprobe' 'revoke-windows-grid.png'
        Set-ItemProperty $themeKey AppsUseLightTheme 0
        Set-ItemProperty $themeKey SystemUsesLightTheme 0
        Start-Sleep 2
        Capture 'Internet for antigravityprobe' 'revoke-windows-grid-dark.png'
    }

    Check 'Antigravity host allowlist' {
        $changed.Add('Internet for antigravityprobe')
        Set-Switch 'Internet for antigravityprobe' $false
        Wait-For { Has-InternetRule $ag } 45 | Out-Null
        if (-not (Probe-Tcp $ag 'accounts.google.com')) { throw 'The allowed Google auth host was blocked.' }
        if (Probe-Tcp $ag 'example.com') { throw 'An unrelated public host remained reachable.' }
    }
    Check 'VSCodium without built-in hosts' {
        $changed.Add('Internet for vscodiumprobe')
        Set-Switch 'Internet for vscodiumprobe' $false
        Wait-For { Has-InternetRule $vs } 45 | Out-Null
        if (Probe-Tcp $vs 'example.com') { throw 'A no-host app reached an unrelated public host.' }
    }
    Check 'new version firewall repair' {
        New-Item -ItemType Directory -Force -Path (Split-Path $agNew) | Out-Null
        Copy-Item $ag $agNew
        $held.Add((Start-Process -FilePath $agNew -ArgumentList 'hold' -PassThru))
        Wait-For { Has-InternetRule $agNew } 60 | Out-Null
        if (Probe-Tcp $agNew 'example.com') { throw 'A new version escaped the Internet limit.' }
    }
    Check 'temporary updater does not break repair' {
        $tempProgram = Join-Path (Split-Path $ag) 'Updater.tmp'
        New-Item -ItemType HardLink -Path $tempProgram -Target $ag | Out-Null
        $logPath = Join-Path $env:LOCALAPPDATA 'Revoke\Revoke.log'
        $before = @(Get-Content $logPath -ErrorAction SilentlyContinue).Count
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $tempProgram
        $startInfo.Arguments = 'hold'
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $updater = [System.Diagnostics.Process]::Start($startInfo)
        if (-not $updater) { throw 'Could not start the PE updater with a .tmp path.' }
        $held.Add($updater)
        Start-Sleep 5
        if (-not (Has-InternetRule $agNew)) { throw 'The executable version lost its block after the updater started.' }
        $newLog = @(Get-Content $logPath -ErrorAction SilentlyContinue | Select-Object -Skip $before) -join "`n"
        if ($newLog -match 'E_INVALIDARG|Value does not fall within the expected range') { throw 'The updater caused an invalid firewall rule.' }
        Record 'temporary updater network coverage' 'skip' 'Windows Firewall rejects .tmp program paths; its own connections are outside this path-based block.'
    }
    Check 'local network firewall block' {
        $changed.Add('Local network for antigravityprobe')
        Set-Switch 'Local network for antigravityprobe' $false
        Wait-For { Has-LocalRule $ag } 45 | Out-Null
        if ($lanPort) {
            if (Probe-Tcp $ag $gateway $lanPort) { throw "The gateway remained reachable on TCP $lanPort." }
        } else {
            Record 'local network socket' 'skip' 'No open gateway TCP port was found for a live socket check.'
        }
        Set-Switch 'Local network for antigravityprobe' $true
    }
    if (Find-Ui 'Internet for ChatGPT') {
        Check 'installed ChatGPT Internet toggle' {
            $changed.Add('Internet for ChatGPT')
            Set-Switch 'Internet for ChatGPT' $false
            Wait-For {
                @((Get-NetFirewallRule -DisplayGroup 'Revoke' -ErrorAction SilentlyContinue) |
                    Where-Object { $_.DisplayName -like '*ChatGPT*internet*' -and $_.Enabled -eq 'True' }).Count -ge 2
            } 45 | Out-Null
            Set-Switch 'Internet for ChatGPT' $true
        }
    } else { Record 'installed ChatGPT Internet toggle' 'skip' 'ChatGPT is not installed in this guest.' }
    foreach ($name in @('Antigravity', 'Cursor', 'Claude', 'VSCodium')) {
        if (-not (Find-Ui "Internet for $name")) {
            Record "installed $name" 'skip' 'The app is not installed in this guest; the probe exercises its firewall pattern where applicable.'
        }
    }

    Check 'access request defaults to No' {
        $url = 'revoke://request?access=internet&app=antigravityprobe&reason=VM%20escape%20test'
        & $ag protocol $url | Out-Null
        $button = Get-Ui 'No' 30
        if (-not $button.Current.HasKeyboardFocus) { throw 'No was not the focused default.' }
        Capture 'No' 'revoke-windows-access-request.png'
        Invoke-Ui 'No'
        Start-Sleep 2
        if (Find-Ui 'No') { throw 'The declined prompt stayed open.' }
    }
    Check 'temporary Internet grant and expiry' {
        $url = 'revoke://request?access=internet&minutes=1&reason=VM%20temporary%20grant'
        $requestInfo = New-Object System.Diagnostics.ProcessStartInfo
        $requestInfo.FileName = $vs
        $requestInfo.Arguments = 'request "' + $revoke + '" "' + $url + '"'
        $requestInfo.UseShellExecute = $false
        $requestInfo.CreateNoWindow = $true
        $requestInfo.RedirectStandardOutput = $true
        $requestInfo.RedirectStandardError = $true
        $request = [System.Diagnostics.Process]::Start($requestInfo)
        if (-not $request) { throw 'Could not launch the CLI request probe.' }
        $held.Add($request)
        Get-Ui 'Yes' 30 | Out-Null
        Invoke-Ui 'Yes'
        if (-not $request.WaitForExit(30000)) { throw 'The CLI request did not finish.' }
        $answer = $request.StandardOutput.ReadToEnd().Trim()
        $errorText = $request.StandardError.ReadToEnd().Trim()
        Mark "CLI request exit=$($request.ExitCode) answer=$answer"
        if ($answer -ne 'yes' -or $request.ExitCode -ne 0) {
            throw "The CLI request returned '$answer' (exit $($request.ExitCode)): $errorText"
        }
        Wait-For { try { Probe-Tcp $vs 'example.com' } catch { $false } } 30 | Out-Null
        Start-Sleep 70
        Wait-For { -not (Probe-Tcp $vs 'example.com') } 45 | Out-Null
    }

    # The screenshot script's link prompt is retained until a guarded link handler is
    # present in the guest. The access request image above is captured by this run.
    Record 'application sign-in and model API' 'skip' 'Requires the app account and app-specific interaction in the VM.'
}
catch {
    Mark "suite failed: $($_.Exception.Message)"
    Record 'suite' 'fail' $_.Exception.Message
}
finally {
    Mark 'cleanup started'
    if ($null -ne $originalTheme) {
        try {
            Set-ItemProperty $themeKey AppsUseLightTheme $originalTheme[0]
            Set-ItemProperty $themeKey SystemUsesLightTheme $originalTheme[1]
        } catch { Record 'restore theme' 'fail' $_.Exception.Message }
    }
    foreach ($name in $changed) {
        try {
            if (-not (Needs-Restore $name)) { continue }
            Set-Switch $name $true
        } catch {
            $errorText = $_.Exception.Message
            try {
                if (Known-BackendState $name) {
                    try { Wait-For { BackendMatches $name $true } 15 | Out-Null }
                    catch { }
                }
                if (Needs-Restore $name) { Record "restore $name" 'fail' $errorText }
            } catch { Record "restore $name" 'fail' $errorText }
        }
    }
    foreach ($process in $held) {
        try { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null } } catch { }
        $process.Dispose()
    }
    $tempProgram = Join-Path (Split-Path $ag) 'Updater.tmp'
    if (Test-Path $tempProgram) { Remove-Item -LiteralPath $tempProgram -Force -ErrorAction SilentlyContinue }
    Mark 'fixtures stopped'
    if ($appStarted) {
        try { Get-Process Revoke -ErrorAction SilentlyContinue | Stop-Process -Force } catch { }
    }
    Mark 'Revoke stopped'
    $report.finished = (Get-Date).ToString('o')
    $report | ConvertTo-Json -Depth 7 | Set-Content -Path (Join-Path $Output 'report.json') -Encoding UTF8
    Mark 'report written'
}
