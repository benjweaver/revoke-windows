# Revoke for Windows

A notification-area app that shows what AI agents such as Claude, ChatGPT/Codex and
Claude Code can do on your PC, and takes it away: it stops them along with everything
they started, switches off their privacy access, keeps them from starting by
themselves, and closes the firewall rules that let your network reach them.

It's the Windows counterpart of [Revoke for macOS](https://github.com/benjweaver/revoke),
built natively with WinUI 3.

## Install

On Windows 10 2004 or later (x64, or ARM64 through its x64 emulation), in PowerShell:

```powershell
irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/install.ps1 | iex
```

That downloads the latest release, checks it against `SHA256SUMS`, puts it in
`%LOCALAPPDATA%\Programs\Revoke` with a Start menu shortcut, and starts it in the
notification area, where its settings open the first time. It needs no admin rights,
so it works on a managed work machine too, unless your organisation blocks unsigned
programs. Only the optional admin helper, installed from Revoke's settings, asks for
admin.

You can run it from an AI agent's terminal too, like Claude Code's or Codex's. Revoke
starts outside the agent's app either way (see
[Running from an agent's terminal](#running-from-an-agents-terminal)).

On macOS, [Revoke for macOS](https://github.com/benjweaver/revoke):

```sh
brew install --cask benjweaver/revoke/revoke
```

### Updating and removing

Revoke doesn't go online by itself, so it doesn't update itself either. To update a
copy installed by the command above to the latest release:

```powershell
irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/update.ps1 | iex
```

If you already have the latest release, that only makes sure Revoke is running. To
remove Revoke, keeping your settings in `%APPDATA%\Revoke`:

```powershell
irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/uninstall.ps1 | iex
```

That also removes the admin helper if it's installed, which asks for admin once, and
leaves the firewall as it was: rules Revoke switched off go back on, and its own go.

### Other ways to install

Otherwise, download `Revoke-<version>-windows-x64.zip` from the
[Releases page](https://github.com/benjweaver/revoke-windows/releases), check it
against `SHA256SUMS`, unzip it anywhere and run `Revoke.exe`. Or build it yourself,
as described under [Build](#build).

## Why it stops apps

macOS gates screen recording and input control behind permissions only System Settings
can grant, so Revoke for macOS takes those permissions back. Windows gates far less:
any app you run can read the screen and drive other apps, with no permission at all.
On Windows, the only way to take that away is to stop the app. So Revoke stops it,
and every process it started: Claude Code sessions, Codex's helpers, MCP servers, and
whatever those ran.

## What it shows and switches

One row per watched app, one switch per column. A switch is orange while access is on.

| Column | On means | Switching off |
|---|---|---|
| Running | The app, its helpers or its service are running | Stops the app, its whole process tree, and its service (which can start again with Windows or when the app asks) |
| Startup | It opens when you sign in, as Task Manager's Startup apps list shows | Turns off its startup task or Run entry |
| Service | A Windows service it installed is allowed to run. Task Manager's Startup apps list leaves these out | Stops the service and keeps it stopped until you switch it back on. **This can break the app**: features that need the service stop working. Revoke asks first |
| Screen | It may capture the screen through Windows' screenshot API | Denies it in Settings › Privacy & security |
| Camera, Mic, Location | It's allowed to use them | Denies it. A red dot means it's using one right now |
| Network | Devices on your network can connect to it, or it can reach them | Switches off its inbound firewall rules and blocks it from your local network (asks for admin) |

Switching a privacy column back on opens Settings, where only you can grant access.

Apps install services because they need them: Claude's Cowork features run in
CoworkVMService, for one. Switching one off means Revoke stops it whenever it starts, at
boot or when the app starts it, until you switch it back on. Revoke confirms before
stopping a service, and marks one it keeps stopped.

Claude's and ChatGPT's services start with Windows. To keep the apps working but stop
that, switch on **Apps' services start only when the apps start them** in Settings.
Windows' service API lets only the package installer change a packaged app's service,
so Revoke sets it to Manual in the service's registry key, through the admin helper,
from the next restart, and sets it again if an app update puts it back. Claude's service
has a start trigger, so Windows starts it when Claude connects to it; Codex starts its
own.

**Revoke All Watched** does every column for every watched app, behind one admin
prompt. Apps signed by Anthropic and OpenAI are watched by default; any other app with
a window open can be added in Settings. A watched program that only runs because
another watched app started it (Codex's node and code-mode helpers, Claude Code inside
Claude) shows in that app's row, and stops with it.

It can also stop watched apps automatically, if you turn these on in Settings:

- **when an app's last window closes.** Claude and ChatGPT keep running in the
  notification area after you close their windows. This stops them instead, and also
  stops anything they started that's still running after they quit.
- **after a time limit**, from 15 minutes to 4 hours after the app started.
- **when you lock the PC or it sleeps.**

Automatic stops leave services and firewall rules alone, so an admin prompt never
appears out of nowhere.

## What it found on a real PC

- Claude installs **CoworkVMService**, which runs as LocalSystem and starts with
  Windows, with firewall rules that let any device on the network connect to it.
- ChatGPT installs **CodexSandboxService**, also LocalSystem and automatic.
- Both apps have inbound firewall rules for their main programs, created when they
  asked to "allow access" on first launch.
- Codex runs Computer Use, a node runtime and a code-mode host as separate programs,
  signed by OpenAI.

## What it can't do, and why

- **No permission controls input or screen reading.** Stopping the app is the only lever.
- **The Screen column covers Windows' screenshot API only** (Windows.Graphics.Capture).
  Older ways of reading the screen don't ask.
- **Desktop programs share one switch** per privacy capability ("Let desktop apps
  access your camera"). For a program like Claude Code, Revoke shows when it's using
  one, but can't switch it off for that program alone; stopping it ends the use.
- **Firewall rules name programs, not process trees.** A command an app runs, like
  `curl`, isn't covered by the app's block. DNS stays open so the internet keeps
  working, since Chromium-based apps send it straight to the router.
- **Updates move programs.** Packaged apps install each version in a new folder. When
  that happens after Revoke blocked an app, the Network switch shows a warning; switch
  it off again to cover the new version.

## How it changes things

Everything Revoke reads needs no admin rights. Most changes don't either: privacy and
startup switches live in your part of the registry, and stopping your own processes is
yours to do. Services, firewall rules and machine-wide startup entries need admin.

Revoke makes those changes through Windows' own interfaces, with no scripts: the
Service Control Manager for services, the firewall's management provider to switch
rules on and off and delete them by their exact ID, the Windows Firewall API to create
rules, and the registry for startup entries.

### The admin helper

So those don't ask every time, Revoke can install a helper from Settings, behind one
UAC prompt: a small Windows service, `RevokeHelper`, in
`C:\Program Files\Revoke\Helper`, where only admins can replace it. It listens on a
named pipe that only your Windows account can open, and Revoke only talks to it after
checking with the service manager that the pipe belongs to that service.

Any program running as you could talk to the helper too, so it checks every change
itself and only makes ones that tighten things or undo its own:

- switch off inbound allow rules, and back on only the ones it switched off;
- add and remove rules in Revoke's own firewall group;
- stop, or set to Manual, services from watched developers (Anthropic and OpenAI), and
  put back only start types it changed;
- switch those developers' machine-wide startup entries off and on.

Anything else, like the service of an app you added to the watch list yourself, still
gets a UAC prompt. The helper logs every request to the Application event log under
`RevokeHelper`. Remove it from Settings, also behind one UAC prompt.

Without the helper, Revoke runs the helper program once as admin for each set of
changes, behind one UAC prompt. The changes go on its command line rather than into a
file another program could swap out before it runs. Until Revoke is code-signed, that
prompt names an unknown publisher. Rules Revoke adds are in the firewall group
`Revoke`.

Settings live in `%APPDATA%\Revoke\settings.json`. Nothing leaves the PC.

### Running from an agent's terminal

Claude and ChatGPT install as packaged (MSIX) apps, and a terminal inside one, like
Claude Code's or Codex's, runs in that app's container. So does anything started from
it. Windows keeps such a program's registry writes, and the new files it puts in
AppData, in the app's private storage, where nothing else sees them. A Revoke started
that way would look like it worked while changing nothing: its settings, its "Open at
sign-in" entry, and its privacy and startup switches would all stay inside Claude's or
ChatGPT's container. Stopping processes and services is unaffected, since those don't
go through the registry.

So when Revoke starts, it writes a value to the registry and asks WMI, which reads the
registry from a Windows service outside any container, whether the value is really
there. If it isn't, Revoke starts itself again through Explorer, which launches it as
if you'd opened it from the Start menu, and exits. The install scripts start it through
Explorer too.

## Build

Needs the .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`). Windows 10 2004 or
later; built and tested on Windows 11.

```powershell
dotnet build src/Revoke
dotnet test --project tests/Revoke.Core.Tests
dotnet publish src/Revoke -c Release -o publish
```

To build this checkout and install it the same way the release installs:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The app is self-contained (.NET and the Windows App SDK included), so `publish` runs
on a PC without either installed. Building the app also publishes the helper
(`src/Revoke.Helper`) beside it as one file, `Helper\RevokeHelper.exe`.
`scripts/make-icons.py` redraws the tray icons.

The tests only read your PC, except for stopping processes they start themselves.

## Release

Bump `<Version>` in `Directory.Build.props`, add the version's section to
`CHANGELOG.md`, then commit and push. `scripts\release.ps1` does the rest: it builds the
app, zips it with a `SHA256SUMS` file, and publishes a GitHub release with that
changelog section as its notes, which the install script then finds. It needs the
GitHub CLI, signed in.

## License

GPL-3.0-or-later.
