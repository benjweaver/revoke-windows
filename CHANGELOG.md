# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Each release's notes on GitHub come
from its section below.

## [0.3.0] - 2026-10-09

### Added

- **When a watched app quits**, in Settings: once the last open app from a developer
  quits, Revoke switches off links, startup, and the privacy switches for all of that
  developer's watched apps, as Revoke for macOS does. Off by default.
- **Give back** under a new Links section in Settings, which gives every app its own
  links and files back, as uninstalling does.
- A log of everything Revoke does, in `%LOCALAPPDATA%\Revoke\Revoke.log`: each change,
  each automatic stop, and each link it stood in for, with what you answered.
- A line under ChatGPT ("Includes Codex"), Claude's Claude Code ("Runs Claude's Code
  tab"), and Codex Computer Use, saying what each is, in the panel and Settings.

### Changed

- When a command opens a link, like `curl` or a script in a terminal, the question says
  which app it runs in: "A command (curl.exe) in Windows Terminal".
- Buttons and menus use Windows' sentence case: **Revoke all watched**, **End all
  tasks**.
- Lists in messages use the serial comma: "Claude, ChatGPT, and Claude Code".
- Claude Code installed with winget is named Claude Code.
- Settings says what Windows doesn't let Revoke do about links and about one program
  driving another.

### Fixed

- Switching Network off, and Revoke all watched, failed with "Disable rule {…}: Invalid
  object path" for any app with inbound firewall rules, such as Claude's and ChatGPT's
  "allow access" rules, so those rules stayed on. Revoke now finds each rule by its ID and
  switches it off and back on. Update the admin helper in Settings after installing.
- Building from a fresh checkout with `scripts\install.ps1` or `scripts\release.ps1`
  failed because the helper's packages weren't restored.

## [0.2.0] - 2026-10-09

### Added

- A **Links** column. Web pages, emails, documents and other apps can open an agent with
  a link (`claude://`, `codex://`, `claude-cli://`) or a file (`.skill`), carrying
  instructions for it, even while it's stopped. Switched off, Revoke opens in the app's
  place, shows the whole link and what's opening it, and opens the app only if you say
  so. It needs no admin, keeps working while Revoke isn't running, and takes links back
  when an app registers them again. Revoke All Watched and the automatic stops switch it
  off too.
- **End task** when you right-click a running app in the panel: it stops the app,
  everything it started, and its service, like switching Running off. Handy for an app,
  or a helper it left behind, running with no window to close.
- **End All Tasks**, beside Revoke All Watched and in the tray menu: it stops every
  watched app that way, and leaves the other switches as they are.

### Changed

- Uninstalling puts every app's links back.

## [0.1.6] - 2026-10-08

### Fixed

- The note after Revoke acts on its own now says what it did, like "Stopped Claude
  when its last window closed", instead of "Revoked access" for everything. An app
  that quit by itself is no longer reported as stopped.

## [0.1.5] - 2026-10-08

### Added

- Right-click an app in the panel to hide it from the list of other apps that can
  capture the screen, like Snipping Tool, or to watch it or stop watching it. Hiding
  doesn't change the app's access. Hidden apps are listed in Settings, with a Show
  button to bring each one back.

## [0.1.4] - 2026-10-08

### Added

- The panel shows a banner when the admin helper isn't running, with a Start button,
  and when it's out of date, or not installed while an option needs it. Settings marks
  a stopped helper in red.

### Changed

- New installs stop watched apps when their last window closes, and set their services
  to start only when the apps start them (once the admin helper is installed), by
  default. Existing settings are kept.

### Fixed

- With services set to start on demand and the helper stopped, every refresh waited
  1.5 seconds for the helper.

## [0.1.3] - 2026-10-08

### Added

- Settings > General > **Apps' services start only when the apps start them**: sets
  watched apps' services, like Claude's CoworkVMService, from Automatic to Manual, so
  they no longer start with Windows but the apps can still start them. For packaged
  apps' services this is written to the registry by the admin helper, and written again
  if an app update sets it back. Update the helper after installing.

### Changed

- Tooltips stay open while hovered instead of closing when the panel refreshes.
- The Service column shows whether the service is running: a green dot while it runs,
  a grey ring while it's stopped.
- The Service tooltip says how the service really starts, read from Windows: with
  Windows, or only when an app starts it, and whether Windows starts it on request.

## [0.1.2] - 2026-10-07

### Fixed

- Revoke started from a terminal inside another app, like Claude Code's or Codex's,
  inherited that app's container, so Windows kept its settings, its "Open at sign-in"
  entry, and its privacy and startup changes in that app's private storage, where they
  did nothing. Revoke now notices when it starts and relaunches itself outside, and the
  install scripts start it through Explorer.

## [0.1.1] - 2026-10-07

### Fixed

- Running now shows on while an app's service is running, even with the app
  closed, and the row says "Service running". Switching Running off stops the
  service too, without admin for packaged services like Claude's, and so does
  stopping an app automatically when its last window closes. Service now means
  whether the service may run at all.

## [0.1.0] - 2026-10-07

### Added

- A notification-area panel with a switch per app for Running, Startup, Service,
  Screen capture, Camera, Microphone, Location and Local network. The tray lock opens
  while a watched app is running.
- Switching Running off stops the app and every process it started. Helpers an app
  starts, like Codex's or Claude Code inside Claude, show in its row and stop with it.
- Startup matches Task Manager's Startup apps. Service covers Windows services an
  app installed: switching it off stops the service and keeps it stopped until you
  switch it back on, after asking, since that can break the app.
- Privacy switches for screen capture, camera, microphone and location, with a dot
  while one is in use. Switching one on opens Settings, where only you can grant it.
- Local network: switches off the firewall rules that let your network reach an
  app, and blocks it from devices on your network.
- Revoke All Watched, and automatic stops when an app's last window closes, after a
  time limit, or when the PC locks or sleeps.
- An admin helper, installed once from Settings, that makes firewall and service
  changes for Anthropic's and OpenAI's apps without a UAC prompt each time.
- Apps signed by Anthropic and OpenAI are watched by default.
- A one-line install, update and uninstall in PowerShell.

[0.3.0]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.3.0
[0.2.0]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.2.0
[0.1.6]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.6
[0.1.5]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.5
[0.1.4]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.4
[0.1.3]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.3
[0.1.2]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.2
[0.1.1]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.1
[0.1.0]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.0
