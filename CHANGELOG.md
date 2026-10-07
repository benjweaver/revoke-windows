# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Each release's notes on GitHub come
from its section below.

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

[0.1.0]: https://github.com/benjweaver/revoke-windows/releases/tag/v0.1.0
