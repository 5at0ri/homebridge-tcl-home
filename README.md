# Homebridge TCL Home

A Homebridge plugin for TCL Home air conditioners that brings your AC units into Apple HomeKit.

## Supported Devices

Currently tested and working with:
- TCL P09F4CSW1K Portable Air Conditioner
- Likely compatible with other TCL Home app A/Cs but will need tweaking for it

## Features

- 🌡️ Temperature control (18-30°C)
- ❄️ Cooling mode control
- 💨 Fan mode with speed control (Low/High)
- 😴 Sleep mode toggle
- 📱 HomeKit integration (mostly)
- 🏠 Siri voice control
- 🔄 Bidirectional sync (device changes reflect in HomeKit - semi working)

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

```

### Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `username` | Yes | Your TCL Home app email |
| `password` | Yes | Your TCL Home app password |
| `debugMode` | No | Enable detailed logging (default: false) |

## Setup Instructions

1. **Download TCL Home app** and create an account
2. **Add your AC** to the TCL Home app
3. **Install this plugin** in Homebridge
4. **Configure** with your TCL Home credentials
5. **Restart Homebridge**

Your AC should appear in the Home app automatically!

## HomeKit Controls

### Main Thermostat
- **Power**: On/Off
- **Mode**: Off, Cool, Auto (Fan)
- **Temperature**: 18-30°C target temperature

### Additional Controls
- **Sleep Mode Switch**: Toggle sleep mode
- **Fan Speed**: Low (50%), High (100%)

## Troubleshooting

### Debug Mode
Enable `debugMode: true` in config to see detailed logs.

### Common Issues
- **Authentication failed**: Check email/password are correct
- **Device not found**: Ensure AC is connected in TCL Home app
- **Commands not working**: Try restarting Homebridge

## Credits

This plugin is inspired by and builds upon the excellent work done by [nemesa](https://github.com/nemesa) in the [ha-tcl-home-unofficial-integration](https://github.com/nemesa/ha-tcl-home-unofficial-integration) project for Home Assistant.

Special thanks for the API documentation and authentication flow analysis.

## Contributing

This plugin was created to get basic functionality working. If you'd like to add support for more devices or features:

1. Fork this repository to add your own improvements or add different models. I'm a noob so I've only just got it working with my specific model right now.

## License

MIT License - see LICENSE file for details.

## Disclaimer

This plugin is not affiliated with TCL. Use at your own risk.
