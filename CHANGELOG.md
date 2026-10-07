# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A notification-area panel with a switch per app for Running, Startup, Screen
  capture, Camera, Microphone, Location and Local network. The tray lock opens while a
  watched app is running.
- Stopping an app stops every process it started, and its Windows service.
- Startup, privacy and firewall switches, with changes that need admin gathered into
  one UAC prompt.
- Revoke All Watched, and automatic stops when an app's last window closes, after a
  time limit, or when the PC locks or sleeps.
- Helpers an app starts show in its row and stop with it.
- Apps signed by Anthropic and OpenAI are watched by default.
- An admin helper, installed once from Settings, that makes firewall and service
  changes for watched developers' apps without a UAC prompt each time.
