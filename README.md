# Homebridge TCL Home

A rudimentary Homebridge plugin for TCL Home air conditioners that brings your AC units into Apple HomeKit with full bidirectional control and real-time synchronisation.

## Supported Devices

Currently tested and working with:
- TCL P09F4CSW1K Portable Air Conditioner
- Maybe other TCL Home app connected A/Cs (may require configuration)

## Features

- 🌡️ **Smart Temperature Control** (18-30°C) - automatically enabled/disabled based on mode
- ❄️ **AC Cooling Mode** - full air conditioning with temperature control
- 💨 **Pure Fan Mode** - fan-only operation without cooling or dehumidifying
- 😴 **Sleep Mode Toggle** - energy-efficient sleep operation
- 📱 **Real-time HomeKit Integration** - instant bidirectional sync
- 🏠 **Full Siri Voice Control** - "Set the AC to 22 degrees", "Turn on auto mode"
- ⚡ **Ultra-fast Polling** - 3-second updates detect manual device changes instantly
- 🎛️ **Context-Aware Fan Control** - separate speed memory for Cool vs Fan modes
- 🔄 **Enhanced Change Detection** - optimized sync prevents unnecessary updates
- 🛡️ **Robust Error Handling** - automatic credential refresh and connection recovery
- 🚫 **Simplified Mode Mapping** - dehumidify modes excluded for cleaner interface

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

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `username` | Yes | - | Your TCL Home app email address |
| `password` | Yes | - | Your TCL Home app password |
| `debugMode` | No | `false` | Enable detailed logging for troubleshooting |
| `appLoginUrl` | No | Auto-configured | TCL authentication endpoint |
| `cloudUrls` | No | Auto-configured | TCL cloud services endpoint |
| `appId` | No | Auto-configured | TCL application identifier |

### Example Configuration

```json
{
  "platforms": [
    {
      "platform": "TclHome",
      "name": "TCL Home",
      "username": "your.email@example.com",
      "password": "your_tcl_password",
      "debugMode": false
    }
  ]
}
```

## Setup Instructions

1. **Download TCL Home app** and create an account
2. **Add your AC** to the TCL Home app
3. **Install this plugin** in Homebridge
4. **Configure** with your TCL Home credentials
5. **Restart Homebridge**

Your AC should appear in the Home app automatically!

## HomeKit Controls

### Main Thermostat
- **Power**: On/Off control
- **Mode Selection**:
  - **Off**: Device powered off
  - **Cool**: Full AC cooling with temperature control (workMode 0)
  - **Auto**: Pure fan mode - air circulation only (workMode 2)
- **Temperature**: 18-30°C target (automatically enabled in Cool mode, disabled in Auto/Fan mode)

### Additional Controls
- **Night Mode Switch**: Night operation toggle
- **AC Fan Control**: Intelligent fan speed management
  - **Cool Mode**: Controls AC compressor fan speed during cooling
  - **Auto/Fan Mode**: Controls pure fan speed for air circulation
  - **Speed Levels**: Low (50% = 1), High (100% = F2)
  - **Context Memory**: Remembers separate speed settings for each mode

## Mode Mapping Details

| HomeKit Mode | AC Function | Temperature Control | Use Case |
|--------------|-------------|-------------------|----------|
| **Cool** | AC Cooling (workMode 0) | ✅ Enabled | Full air conditioning with cooling |
| **Auto** | Pure Fan (workMode 2) | ❌ Disabled | Air circulation without cooling |
| **Off** | Power Off | ❌ Disabled | Device shutdown |

**Note**: Dehumidify modes are intentionally excluded for simplified operation.

## Troubleshooting

### Debug Mode
Enable `debugMode: true` in your configuration to see detailed logs including:
- Real-time device state changes
- Mode mapping decisions  
- AWS credential refresh attempts
- Polling sync information

### Common Issues

**Authentication Problems**
- **Authentication failed**: Verify your TCL Home app email/password are correct
- **Credentials expired**: Plugin automatically handles this - wait for re-authentication
- **AWS errors**: Connection will auto-recover with built-in retry logic

**Device Communication**
- **Device not found**: Ensure AC is connected and working in TCL Home app
- **Commands not responsive**: Check if device is online in TCL Home app
- **Slow updates**: Plugin polls every 3 seconds - manual changes appear quickly

**Mode Issues**
- **Wrong mode displayed**: Plugin maps workMode 0→Cool, workMode 2→Auto/Fan
- **Temperature control missing**: Only available in Cool mode (by design)
- **Fan speeds not working**: Separate speeds for Cool vs Auto modes are remembered

**Performance**
- **High CPU usage**: Disable debug mode if enabled for production use
- **Network issues**: Plugin includes automatic credential refresh and error recovery

## Credits

This plugin is inspired by and builds upon the excellent work done by [nemesa](https://github.com/nemesa) in the [ha-tcl-home-unofficial-integration](https://github.com/nemesa/ha-tcl-home-unofficial-integration) project for Home Assistant.

Special thanks for the API documentation and authentication flow analysis.

## Usage Examples

### Siri Voice Commands
- *"Set the AC to 22 degrees"* - Changes to Cool mode and sets temperature
- *"Turn on the fan"* - Switches to Auto/Fan mode for air circulation
- *"Turn on sleep mode"* - Enables energy-efficient sleep operation
- *"Set the AC fan to high"* - Changes fan speed to 100% (F2)
- *"Turn off the air conditioner"* - Powers off the device

### Home App Controls
1. **Temperature Control**: Use the thermostat when in Cool mode
2. **Mode Switching**: Tap the mode button to switch between Cool/Auto/Off
3. **Fan Speed**: Use the separate fan accessory to control air circulation
4. **Sleep Mode**: Toggle the sleep switch for overnight operation

## Contributing

Contributions are welcome! This plugin has been extensively tested and improved for reliability. 

### Development Setup
1. Fork this repository
2. Install dependencies: `npm install`
3. Make your improvements
4. Test with your TCL devices

### Adding Device Support
If you have a different TCL model:
1. Enable debug mode to see device capabilities
2. Check the workMode mappings for your device
3. Adjust mode constants if needed
4. Test all functionality thoroughly


### Mode Mapping Reference
```javascript
// HomeKit → TCL Device
Cool Mode → workMode: 0 (AC cooling with compressor)
Auto Mode → workMode: 2 (Pure fan, no cooling)
Off Mode → powerSwitch: 0

// Excluded: workMode 1 & 3 (dehumidify modes)
```

## License

MIT License - see LICENSE file for details.

## Disclaimer

This plugin is not affiliated with TCL. Use at your own risk.
