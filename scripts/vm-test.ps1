# Build this checkout and run the live firewall, update, request, and screenshot checks
# in a signed-in Aviary Windows VM. The VM needs Aviary SSH access and an existing
# network connection. An out-of-date RevokeHelper asks the person at the VM for UAC.
#
#   powershell -ExecutionPolicy Bypass -File scripts\vm-test.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\vm-test.ps1 -Machine <Aviary ID>
param([string]$Machine, [switch]$SkipBuild, [string]$ExistingStage, [switch]$UpdateScreenshots)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($ExistingStage -and $ExistingStage -notmatch '^RevokeVmTest-\d{8}-\d{6}$') {
    throw '-ExistingStage must name a stage created by this script (RevokeVmTest-YYYYMMDD-HHMMSS).'
}
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path $repo 'publish\vm-test'
$mcp = Join-Path $env:LOCALAPPDATA 'Programs\Aviary\aviary-mcp.exe'
if (-not (Test-Path $mcp)) { throw "Aviary MCP is missing at $mcp. Install Aviary first." }

function Aviary([string]$name, [hashtable]$arguments) {
    $payload = @{ jsonrpc = '2.0'; id = 1; method = 'tools/call'; params = @{ name = $name; arguments = $arguments } } |
        ConvertTo-Json -Depth 8 -Compress
    $line = $payload | & $mcp
    if ($LASTEXITCODE -ne 0) { throw "Aviary MCP $name exited $LASTEXITCODE." }
    $reply = $line | ConvertFrom-Json
    if ($reply.error) { throw "Aviary MCP $name`: $($reply.error.message)" }
    if ($reply.result.isError) { throw "Aviary $name`: $($reply.result.content[0].text)" }
    if ($name -eq 'screenshot') { return $reply.result.content[0].data }
    return $reply.result.content[0].text | ConvertFrom-Json
}

$machines = Aviary 'list_machines' @{}
if ($machines.Count -eq 1 -and $machines[0] -is [array]) { $machines = $machines[0] }
if ($Machine) {
    $matches = @($machines | Where-Object { $_.id -eq $Machine -or $_.name -eq $Machine })
} else {
    $matches = @($machines | Where-Object { $_.os -eq 'Windows' -and $_.status -eq 'Running' -and $_.ssh.ready })
}
if ($matches.Count -ne 1) { throw "Choose one running Windows VM with Aviary SSH using -Machine <ID>. Found $($matches.Count) matches." }
$vm = $matches[0]
if ($vm.status -ne 'Running' -or -not $vm.ssh.ready) { throw "$($vm.name) must be running, signed in, and SSH-ready." }
$config = Join-Path $env:LOCALAPPDATA "Aviary\Machines\$($vm.id)\access\ssh_config"
if (-not (Test-Path $config)) { throw "Aviary SSH config is missing for $($vm.id)." }
$ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
$scp = Join-Path $env:WINDIR 'System32\OpenSSH\scp.exe'
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$guestName = if ($ExistingStage) { $ExistingStage } else { "RevokeVmTest-$runId" }
$guestStage = "`$env:USERPROFILE\Downloads\$guestName"
$outputName = "RevokeVmTest-results-$runId"
$guestOutput = "`$env:USERPROFILE\Downloads\$outputName"
$archive = Join-Path $work "$guestName.zip"
$localResults = Join-Path $work "results\$runId"

function Guest([string]$code) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ProgressPreference = 'SilentlyContinue'; `$ErrorActionPreference = 'Stop'; $code"))
    $output = & $ssh -F $config -o BatchMode=yes guest "powershell -NoProfile -NonInteractive -EncodedCommand $encoded" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "VM command failed: $output" }
    return ($output | Where-Object { $_ -notlike '#< CLIXML*' -and $_ -notlike '<Objs *' }) -join "`n"
}

Write-Host 'Checking that Aviary can run a task in the signed-in VM desktop...'
$readyName = "RevokeVmReady-$runId"
$ready = @"
`$service = New-Object -ComObject Schedule.Service
`$service.Connect()
`$folder = `$service.GetFolder('\')
`$path = Join-Path `$env:USERPROFILE 'Downloads\$readyName.txt'
`$definition = `$service.NewTask(0)
`$definition.Principal.UserId = "`$env:COMPUTERNAME\`$env:USERNAME"
`$definition.Principal.LogonType = 3
`$definition.Settings.Enabled = `$true
`$definition.Settings.AllowDemandStart = `$true
`$action = `$definition.Actions.Create(0)
`$action.Path = 'cmd.exe'
`$action.Arguments = '/c echo ready > "' + `$path + '"'
`$task = `$folder.RegisterTaskDefinition('$readyName', `$definition, 6, `$null, `$null, 3)
`$task.Run(`$null) | Out-Null
for (`$i = 0; `$i -lt 12 -and -not (Test-Path `$path); `$i++) { Start-Sleep 1 }
`$worked = Test-Path `$path
if (-not `$worked) { `$task.Stop(0) }
`$folder.DeleteTask('$readyName', 0)
Remove-Item `$path -ErrorAction SilentlyContinue
if (-not `$worked) { throw 'The signed-in VM desktop did not execute an interactive task. Unlock or reconnect its desktop, then retry.' }
"@
Guest $ready | Out-Null

if (-not $SkipBuild) {
    Write-Host 'Publishing Revoke and the self-contained VM probe...'
    & dotnet restore (Join-Path $repo 'src\Revoke.Helper') --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Helper restore failed.' }
    & dotnet publish (Join-Path $repo 'src\Revoke') -c Release -o (Join-Path $work 'Revoke') --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Revoke publish failed.' }
    & dotnet publish (Join-Path $repo 'tests\Revoke.VmProbe') -c Release -o (Join-Path $work 'Probe') --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'VM probe publish failed.' }
}
$probe = Join-Path $work 'Probe\RevokeVmProbe.exe'
$app = Join-Path $work 'Revoke\Revoke.exe'
if (-not (Test-Path $app) -or -not (Test-Path $probe)) { throw 'Published Revoke or probe is missing. Run without -SkipBuild.' }

Copy-Item (Join-Path $PSScriptRoot 'vm-test-guest.ps1') (Join-Path $work 'vm-test-guest.ps1') -Force
if (-not $ExistingStage) {
    Write-Host "Staging $($vm.name) ($($vm.id))..."
    Compress-Archive -Path (Join-Path $work 'Revoke'), (Join-Path $work 'Probe'), (Join-Path $work 'vm-test-guest.ps1') -DestinationPath $archive -Force
    Aviary 'put_file' @{ machine = $vm.id; local_path = $archive } | Out-Null
    Guest "`$zip = Join-Path `$env:USERPROFILE 'Downloads\$guestName.zip'; Expand-Archive -Path `$zip -DestinationPath $guestStage -Force; if (-not (Test-Path (Join-Path $guestStage 'Revoke\Revoke.exe')) -or -not (Test-Path (Join-Path $guestStage 'Probe\RevokeVmProbe.exe'))) { throw 'The VM archive did not extract fully.' }; Remove-Item -LiteralPath `$zip -Force" | Out-Null
} else {
    Write-Host "Using the already-staged $guestName in $($vm.name)."
}

Write-Host 'Starting the signed-in desktop test task. Approve the VM UAC prompt if Update appears.'
$taskName = "RevokeVmTask-$runId"
$start = @"
`$stagePath = Join-Path `$env:USERPROFILE 'Downloads\$guestName'
`$outputPath = Join-Path `$env:USERPROFILE 'Downloads\$outputName'
`$service = New-Object -ComObject Schedule.Service
`$service.Connect()
`$folder = `$service.GetFolder('\')
`$definition = `$service.NewTask(0)
`$definition.RegistrationInfo.Description = 'Revoke VM test suite'
`$definition.Principal.UserId = "`$env:COMPUTERNAME\`$env:USERNAME"
`$definition.Principal.LogonType = 3
`$definition.Principal.RunLevel = 0
`$definition.Settings.Enabled = `$true
`$definition.Settings.AllowDemandStart = `$true
`$definition.Settings.ExecutionTimeLimit = 'PT20M'
`$action = `$definition.Actions.Create(0)
`$action.Path = 'powershell.exe'
`$action.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path `$stagePath 'vm-test-guest.ps1') + '" -Stage "' + `$stagePath + '" -Output "' + `$outputPath + '"'
`$task = `$folder.RegisterTaskDefinition('$taskName', `$definition, 6, `$null, `$null, 3)
`$task.Run(`$null) | Out-Null
"@
Guest $start | Out-Null

$deadline = (Get-Date).AddMinutes(15)
$runnerStarted = Get-Date
do {
    Start-Sleep 5
    $done = (Guest "Write-Output (Test-Path (Join-Path $guestOutput 'report.json'))").Trim()
    if ($done -eq 'True') { break }
    if ((Get-Date) - $runnerStarted -gt [TimeSpan]::FromSeconds(20)) {
        $state = (Guest "Write-Output (Get-ScheduledTask -TaskName '$taskName').State").Trim()
        if ($state -eq 'Ready') {
            # The task can finish between the report check and the state check.
            $done = (Guest "Write-Output (Test-Path (Join-Path $guestOutput 'report.json'))").Trim()
            if ($done -eq 'True') { break }
            Start-Sleep 2
            $done = (Guest "Write-Output (Test-Path (Join-Path $guestOutput 'report.json'))").Trim()
            if ($done -eq 'True') { break }
            $progress = Guest "`$path = Join-Path $guestOutput 'progress.log'; if (Test-Path `$path) { Get-Content `$path -Tail 8 }"
            Guest "`$service = New-Object -ComObject Schedule.Service; `$service.Connect(); `$service.GetFolder('\').DeleteTask('$taskName', 0)" | Out-Null
            throw "VM runner exited without a report. Guest progress: $progress"
        }
    }
} while ((Get-Date) -lt $deadline)
if ($done -ne 'True') {
    Guest "`$service = New-Object -ComObject Schedule.Service; `$service.Connect(); `$service.GetFolder('\').DeleteTask('$taskName', 0)" | Out-Null
    throw "VM test timed out. Staged files remain at $guestName for inspection."
}

New-Item -ItemType Directory -Force -Path $localResults | Out-Null
& $scp -F $config -o BatchMode=yes "guest:Downloads/$outputName/report.json" (Join-Path $localResults 'report.json')
if ($LASTEXITCODE -ne 0) { throw 'Could not retrieve the VM report.' }
foreach ($file in @('revoke-windows-grid.png', 'revoke-windows-grid-dark.png', 'revoke-windows-access-request.png')) {
    if ((Guest "Write-Output (Test-Path (Join-Path $guestOutput '$file'))").Trim() -eq 'True') {
        & $scp -F $config -o BatchMode=yes "guest:Downloads/$outputName/$file" (Join-Path $localResults $file)
        if ($LASTEXITCODE -ne 0) { throw "Could not retrieve $file from the VM." }
    }
}
Guest "`$service = New-Object -ComObject Schedule.Service; `$service.Connect(); `$service.GetFolder('\').DeleteTask('$taskName', 0)" | Out-Null
$report = Get-Content (Join-Path $localResults 'report.json') -Raw | ConvertFrom-Json
$report.checks | Format-Table name, status, detail -AutoSize
Write-Host "VM report and screenshots: $localResults"
if (@($report.checks | Where-Object status -eq 'fail').Count -gt 0) { exit 1 }
if ($UpdateScreenshots) {
    $screenshots = @(
        @('revoke-windows-grid.png', 'revoke-windows-grid.png'),
        @('revoke-windows-grid.png', 'revoke-windows-vm-test-grid.png'),
        @('revoke-windows-grid-dark.png', 'revoke-windows-grid-dark.png'),
        @('revoke-windows-grid-dark.png', 'revoke-windows-vm-test-grid-dark.png'),
        @('revoke-windows-access-request.png', 'revoke-windows-access-request.png')
    )
    foreach ($pair in $screenshots) {
        $source = Join-Path $localResults $pair[0]
        if (-not (Test-Path $source)) { throw "The VM did not capture $($pair[0]), so the screenshots were not updated." }
        Copy-Item $source (Join-Path $repo "docs\screenshots\$($pair[1])") -Force
    }
    Write-Host 'Updated the VM test screenshots in docs/screenshots.'
}
if (-not $ExistingStage) {
    $cleanup = @"
`$downloads = [IO.Path]::GetFullPath((Join-Path `$env:USERPROFILE 'Downloads'))
foreach (`$name in @('$guestName', '$outputName')) {
    if (`$name -notmatch '^RevokeVmTest-(results-)?\d{8}-\d{6}$') { throw 'Unexpected VM test artifact name.' }
    `$target = [IO.Path]::GetFullPath((Join-Path `$downloads `$name))
    if ([IO.Path]::GetDirectoryName(`$target) -ne `$downloads) { throw 'VM test artifact escaped Downloads.' }
    `$item = Get-Item -LiteralPath `$target -Force -ErrorAction SilentlyContinue
    if (`$item) {
        if (`$item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'VM test artifact is a reparse point.' }
        Remove-Item -LiteralPath `$target -Recurse -Force
    }
}
"@
    Guest $cleanup | Out-Null
    Write-Host "Removed this run's staged files from the VM."
}
