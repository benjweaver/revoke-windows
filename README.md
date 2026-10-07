# Revoke for Windows

A notification-area app that shows what AI agents such as Claude, ChatGPT/Codex and
Claude Code can do on your PC, and takes it away: it stops them along with everything
they started, switches off their privacy access, keeps them from starting by
themselves, and closes the firewall rules that let your network reach them.

It's the Windows counterpart of [Revoke for macOS](https://github.com/benjweaver/revoke),
built natively with WinUI 3.

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
| Running | The app, its helpers or its service are running | Stops the app and its whole process tree, and its service (asks for admin) |
| Startup | It opens at sign-in, or its service starts with Windows | Turns off its startup task or Run entry, and sets its service to Manual |
| Screen | It may capture the screen through Windows' screenshot API | Denies it in Settings › Privacy & security |
| Camera, Mic, Location | It's allowed to use them | Denies it. A red dot means it's using one right now |
| Network | Devices on your network can connect to it, or it can reach them | Switches off its inbound firewall rules and blocks it from your local network (asks for admin) |

Switching a privacy column back on opens Settings, where only you can grant access.

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

## Build

Needs the .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`). Windows 10 2004 or
later; built and tested on Windows 11.

```powershell
dotnet build src/Revoke
dotnet test --project tests/Revoke.Core.Tests
dotnet publish src/Revoke -c Release -o publish
```

The app is self-contained (.NET and the Windows App SDK included), so `publish` runs
on a PC without either installed. Building the app also publishes the helper
(`src/Revoke.Helper`) beside it as one file, `Helper\RevokeHelper.exe`.
`scripts/make-icons.py` redraws the tray icons.

The tests only read your PC, except for stopping processes they start themselves.

## License

GPL-3.0-or-later.
