# Publishes a GitHub release of Revoke: builds it, zips it with its checksum, and
# creates the release with the version's CHANGELOG section as its notes.
#
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1
#
# First bump <Version> in Directory.Build.props, add the version's section to
# CHANGELOG.md, and commit and push: the release is made from what's on GitHub.
# packaging\windows\install.ps1 installs the latest release.
#
# Needs the .NET 10 SDK and the GitHub CLI, signed in.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path -Parent $PSScriptRoot

# Runs a program that reports on stderr, which Windows PowerShell 5.1 would otherwise
# turn into a fatal error. Check $LASTEXITCODE afterwards.
function Invoke-Quietly([scriptblock]$command) {
    $ErrorActionPreference = 'Continue'
    & $command 2>&1 | Out-String
}
$flavour = 'windows-x64'

$version = ([xml](Get-Content (Join-Path $repo 'Directory.Build.props'))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $version) { throw 'Directory.Build.props has no <Version>.' }
$tag = "v$version"

# The release has to match a commit that's on GitHub, with nothing left out.
Push-Location $repo
try {
    if (git status --porcelain) { throw 'There are uncommitted changes. Commit and push them first.' }
    git fetch --quiet origin
    if ((git rev-parse HEAD) -ne (git rev-parse '@{u}')) { throw 'This branch and GitHub differ. Push (or pull) first.' }
    Invoke-Quietly { gh release view $tag } | Out-Null
    if ($LASTEXITCODE -eq 0) { throw "$tag is already released. Bump <Version> in Directory.Build.props first." }
}
finally {
    Pop-Location
}

# The notes are the version's CHANGELOG section, up to the next one or the links.
$changelog = Get-Content (Join-Path $repo 'CHANGELOG.md')
$start = [array]::FindIndex($changelog, [Predicate[string]] { param($l) $l -like "## ``[$version``]*" })
if ($start -lt 0) { throw "CHANGELOG.md has no section for $version." }
$notes = $changelog[($start + 1)..($changelog.Length - 1)] |
    ForEach-Object -Begin { $done = $false } -Process { if ($_ -match '^## \[|^\[') { $done = $true }; if (-not $done) { $_ } }
$notes = ($notes -join "`n").Trim()

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe' }
$dist = Join-Path $repo 'dist'
$stage = Join-Path $dist 'Revoke'
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Building Revoke $version..."
& $dotnet publish (Join-Path $repo 'src\Revoke') -c Release -p:Platform=x64 -o $stage --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw "The build failed (exit code $LASTEXITCODE)." }
foreach ($required in 'Revoke.exe', 'Revoke.pri', 'Helper\RevokeHelper.exe') {
    if (-not (Test-Path (Join-Path $stage $required))) { throw "The build has no $required in it." }
}
# Debug symbols stay out of the download.
Get-ChildItem $stage -Recurse -Filter *.pdb | Remove-Item

# One folder named Revoke inside the zip, which install.ps1 expects.
$zipName = "Revoke-$version-$flavour.zip"
$zip = Join-Path $dist $zipName
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$sums = Join-Path $dist 'SHA256SUMS'
[IO.File]::WriteAllText($sums, "$hash  $zipName`n")
$notesFile = Join-Path $dist 'notes.md'
[IO.File]::WriteAllText($notesFile, $notes + "`n")
Write-Host ("{0} is {1:N0} MB" -f $zipName, ((Get-Item $zip).Length / 1MB))

Push-Location $repo
try {
    $target = git rev-parse HEAD
    $output = Invoke-Quietly { gh release create $tag $zip $sums --title "Revoke $version" --notes-file $notesFile --target $target }
    if ($LASTEXITCODE -ne 0) { throw "gh release create failed: $output" }
    Write-Host $output.Trim()
}
finally {
    Pop-Location
}
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Released $tag"
