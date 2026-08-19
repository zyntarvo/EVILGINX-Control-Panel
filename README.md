<p align="center">
  <img src="docs/header.png" alt="EVILGINX Control Panel + Auto Installer" width="720">
</p>

<p align="center">
  <img src="docs/logo.png" alt="ZynTarvo lynx" width="148">
</p>

<p align="center">
  <a href="https://www.youtube.com/watch?v=KupIZHFTL90"><img src="https://img.shields.io/badge/YouTube-Watch%20Demo-ff0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube"></a>
  &nbsp;
  <img src="https://img.shields.io/badge/Ubuntu-20.04%20%7C%2022.04%20%7C%2024.04%20%7C%2026.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Ubuntu">
  &nbsp;
  <img src="https://img.shields.io/badge/Python-3-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
</p>

<p align="center"><b>Created by ZynTarvo</b> · <i>Nothing Is Impossible</i></p>

---

The world’s first web **Control Panel** for [Evilginx](https://github.com/kgretzky/evilginx2) — plus a fully automatic installer.

No Linux wizardry. No coding. Enter the server IP and password, click Install, and get a working Evilginx C2 with a browser dashboard: phishlets, lures, sessions, domains, services.

Built for red teamers, pentesters, and anyone who wants Evilginx running in minutes instead of fighting the terminal for hours.

- Auto-install on Ubuntu
- Web C2 panel with login
- Manage phishlets, lures and captured sessions from the browser

## Demo

[![Watch the demo](https://img.youtube.com/vi/KupIZHFTL90/maxresdefault.jpg)](https://www.youtube.com/watch?v=KupIZHFTL90)

Full walkthrough: **[EVILGINX Control Panel + Auto Installer](https://www.youtube.com/watch?v=KupIZHFTL90)**

## A note on authorship

This project does **not** steal anyone’s work.

[Evilginx2](https://github.com/kgretzky/evilginx2) is the original engine by **Kuba Gretzky (@mrgretzky)**. We clone it cleanly, then add a web control panel and a one-click installer on top — so people who are just starting in cybersecurity can use the tool without living in the command line.

Think of it as a companion: the same Evilginx, made simpler to install and operate.

## Install

**Requirements:** Windows PC with Python 3, and a fresh Ubuntu 20.04 / 22.04 / 24.04 / 26.04 server (root SSH).

1. Clone this repository
2. Double-click `START.bat` (or run `python evilginx_setup.py`)
3. Fill in **IP**, **SSH port**, **username**, **password**
4. Wait for the installer to finish

The installer installs Go 1.20, frees DNS port 53, clones evilginx2, builds it, uploads this panel, and starts both as systemd services.

Panel URL: `http://YOUR_SERVER_IP:8443`  
Login is the same as SSH (user + password).

## Login

<p align="center">
  <img src="docs/screenshots/01-login.png" alt="Login" width="420">
</p>

Encrypted session, username / password, neon lynx mark. Also works on mobile:

<p align="center">
  <img src="docs/screenshots/14-mobile-login.png" alt="Mobile login" width="280">
  &nbsp;
  <img src="docs/screenshots/15-mobile-menu.png" alt="Mobile menu" width="280">
</p>

## Control Panel — every menu

The sidebar is the whole product. Each page below is what you see after login.

<p align="center"><img src="docs/screenshots/15-mobile-menu.png" alt="Sidebar" width="280"></p>

### Dashboard

<p align="center"><img src="docs/screenshots/02-dashboard.png" alt="Dashboard" width="900"></p>

Home screen. At a glance:

| Block | What it shows |
|---|---|
| **Active Phishlets** | How many phishlets are currently enabled |
| **Total Sessions** | All captured visitor sessions |
| **JWT Captured** | Sessions where a JWT was taken (cookie value looks like `eyJ…`) |
| **Server Uptime** | How long the panel host has been up |
| **Sessions Timeline** | Last 7 days: total / JWT / cookies / empty |
| **Session Breakdown** | Donut chart of JWT vs cookies vs empty |
| **Recent JWT Sessions** | Latest successful JWT rows with View / Delete |

### Phishlets

<p align="center"><img src="docs/screenshots/03-phishlets.png" alt="Phishlets" width="900"></p>

YAML modules that tell Evilginx how to proxy a target site.

- **+ New Phishlet** — create a new YAML in the phishlets folder
- **Refresh** — reload the list from disk / Evilginx
- Table: **Name**, **Author**, **Hostname**, **Status** (enabled / disabled), **Visible**
- **Edit** — open the in-browser YAML editor (find / replace / save)
- **Enable / Disable** — toggle live on the running Evilginx process
- **Delete** — remove the phishlet file

<p align="center"><img src="docs/screenshots/11-editor-phishlet.png" alt="Phishlet editor" width="720"></p>

### Configuration

<p align="center"><img src="docs/screenshots/04-configuration.png" alt="Configuration" width="900"></p>

Service control + per-phishlet networking.

- **ONLINE / OFFLINE** — Evilginx process status
- **STOP / RESTART** — stop or bounce the engine
- **Quick Setup** — one wizard: domain, hostname, IPv4, lure path, enable
- Per row: **Edit** hostname / domain / IP / lure / blacklist, **Enable / Disable**, **Delete**

<p align="center"><img src="docs/screenshots/13-editor-config.png" alt="Edit configuration" width="560"></p>

| Field | Meaning |
|---|---|
| **DOMAIN** | Base domain Evilginx answers on |
| **PHISHLET HOSTNAME** | Hostname bound to that phishlet |
| **IPV4 EXTERNAL** | Public IP of the box |
| **LURE PATH** | URL path of the lure (often `/`) |
| **BLACKLIST MODE** | Evilginx blacklist (`off` / unauth / all) |

### Lures

<p align="center"><img src="docs/screenshots/05-lures.png" alt="Lures" width="900"></p>

The links you actually send. Each lure is tied to a phishlet.

- **+ New Lure** — create a lure for a chosen phishlet
- Table: **#**, **Phishlet**, **Path**, **URL**, **Paused** (Active / Paused)
- **Edit** — path, redirect URL, UA filter, Open Graph title / description / image / URL
- **Copy URL** — copy the live lure link
- **Delete** — drop the lure

<p align="center"><img src="docs/screenshots/12-editor-lure.png" alt="Edit lure" width="640"></p>

### File Explorer

<p align="center"><img src="docs/screenshots/06-file-explorer.png" alt="File Explorer" width="900"></p>

Browse the server from the browser: `/root`, `evilginx2`, `evilginx-panel`, phishlets, configs.

- **Up / Home** — navigate
- **New File / New Folder**
- **Make Service** — turn a script into a systemd unit from the UI
- **Refresh**
- Click a file to view / edit (YAML, configs, etc.)
- Columns: **Name**, **Size**, **Modified**, **Perms**

### Services

<p align="center"><img src="docs/screenshots/07-services.png" alt="Services" width="900"></p>

systemd manager so you are not SSH-ing just to restart a daemon.

- Filters: **RUNNING** / **CUSTOM** / **ALL**
- **+ New Service** — register your own unit
- Per service: **Stop**, **Restart**, **Enable / Disable** on boot, **Logs**, **Delete** (custom units)
- `evilginx-panel` is tagged **CUSTOM** — that is this web panel

### Notifications

<p align="center"><img src="docs/screenshots/08-notifications.png" alt="Notifications" width="900"></p>

Telegram alerts when a session actually has tokens — not every empty hit.

- **Telegram Bot Token** + **Chat ID**
- Toggles: master enable, notify on JWT, notify on any cookies / tokens
- **Save Settings** / **Stop** / **Send Test** / **Reset Sent IDs**
- Status line shows whether the watcher is active and how many messages were sent

### Sessions

<p align="center"><img src="docs/screenshots/09-sessions.png" alt="Sessions" width="900"></p>

The captured-session database.

- Filters: **ALL** / **WITH JWT** / **WITH TOKENS** / **EMPTY**
- Search by ID, IP, username
- **Refresh** / **CLEAR DATABASE**
- Columns: ID, phishlet, remote IP, cookie count, JWT badge, username, password, time
- **View** — full session detail (cookies, tokens)
- **Delete** — remove one row

Mobile view stacks the same table as cards:

<p align="center"><img src="docs/screenshots/16-mobile-sessions.png" alt="Mobile sessions" width="280"></p>

### Terminal

<p align="center"><img src="docs/screenshots/10-terminal.png" alt="Terminal" width="900"></p>

A live Evilginx console in the browser (xterm.js). Same commands as SSH: `phishlets`, `lures`, `config`, `sessions`.

- **Restart** / **Stop** / **Start** the Evilginx process from the toolbar
- Output, tables, and the `:` prompt stay on the page — no extra SSH client

## Layout

```
START.bat                 → launch the GUI installer
evilginx_setup.py         → SSH installer (Ubuntu 20.04–26.04)
payload/                  → panel that gets uploaded to the server
  app.py
  templates/              → login + dashboard
  static/                 → lynx logo + favicons
docs/screenshots/         → UI shots from the demo video
```

## Support the work

If this panel saved you time and you want to say thank you, USDT on **Ethereum (ERC-20)** is enough:

```
0xFd051b2267b75C9c2513Cb9BAd546e3C51d5dB44
```

No pressure. Use the tool, learn, and pass it on.

## Credits

- **Evilginx2** — [Kuba Gretzky](https://github.com/kgretzky/evilginx2)
- **Control Panel + Auto Installer** — [ZynTarvo](https://github.com/zyntarvo)

<p align="center"><i>ZynTarvo — Nothing Is Impossible</i></p>
