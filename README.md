# Homebridge TCL Home

A Homebridge plugin for TCL Home air conditioners that brings your AC units into Apple HomeKit.

## Supported Devices

Currently tested and working with:
- TCL P09F4CSW1K Portable Air Conditioner
- Likely compatible with other TCL Home app devices but will need tweaking for it

## Features

- 🌡️ Temperature control (18-30°C)
- ❄️ Cooling mode control
- 💨 Fan mode with speed control (Auto/Low/High)
- 😴 Sleep mode toggle
- 📱 Full HomeKit integration
- 🏠 Siri voice control
- 🔄 Bidirectional sync (device changes reflect in HomeKit)

## Installation

### Via Homebridge UI (Recommended)

1. Open Homebridge UI
2. Go to "Plugins" tab
3. Search for "homebridge-tcl-home"
4. Click "Install"
5. Configure with your TCL Home credentials

### Via Command Line

```bash
npm install -g homebridge-tcl-home
