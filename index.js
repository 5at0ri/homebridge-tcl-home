const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');

module.exports = (homebridge) => {
  homebridge.registerPlatform('homebridge-tcl-home', 'TclHome', TclHomePlatform);
};

class TclHomePlatform {
  constructor(log, config, api) {
    this.log = log;
    this.config = config;
    this.api = api;
    this.accessories = [];

    if (!config || !config.username || !config.password) {
      this.log.error('❌ Username and password are required in config');
      return;
    }

    this.log.info('🚀 TCL Home Plugin Starting...');

    this.tclApi = new TclHomeApi({
      username: config.username,
      password: config.password,
      appLoginUrl: config.appLoginUrl || 'https://pa.account.tcl.com/account/login?clientId=54148614',
      cloudUrls: config.cloudUrls || 'https://prod-center.aws.tcljd.com/v3/global/cloud_url_get',
      appId: config.appId || 'wx6e1af3fa84fbe523',
      debugMode: config.debugMode || false,
      log: this.log
    });

    this.api.on('didFinishLaunching', () => {
      this.discoverDevices();
    });
  }

  async discoverDevices() {
    try {
      this.log.info('🔍 Discovering TCL devices...');
      await this.tclApi.initialize();
      const devices = await this.tclApi.getDevices();
      
      this.log.info(`✅ Found ${devices.length} TCL device(s)`);
      
      for (const device of devices) {
        if (device.category === 'AC') {
          this.log.info(`➕ Adding AC device: ${device.deviceName} (${device.deviceId})`);
          this.addAccessory(device);
        }
      }
    } catch (error) {
      this.log.error('❌ Error discovering devices:', error.message);
    }
  }

  addAccessory(device) {
    const uuid = this.api.hap.uuid.generate(device.deviceId);
    const fanUuid = this.api.hap.uuid.generate(device.deviceId + '-fan');
    
    const existingAccessory = this.accessories.find(acc => acc.UUID === uuid);
    const existingFanAccessory = this.accessories.find(acc => acc.UUID === fanUuid);

    if (existingAccessory) {
      this.log.info('🔄 Updating existing AC accessory:', device.deviceName);
      new TclAirConditioner(this, existingAccessory, device);
    } else {
      this.log.info('🆕 Adding new AC accessory:', device.deviceName);
      const accessory = new this.api.platformAccessory(device.deviceName, uuid);
      new TclAirConditioner(this, accessory, device);
      this.api.registerPlatformAccessories('homebridge-tcl-home', 'TclHome', [accessory]);
      this.accessories.push(accessory);
    }

    if (existingFanAccessory) {
      this.log.info('🔄 Updating existing Fan accessory:', device.deviceName + ' Fan');
      new TclFan(this, existingFanAccessory, device);
    } else {
      this.log.info('🆕 Adding new Fan accessory:', device.deviceName + ' Fan');
      const fanAccessory = new this.api.platformAccessory(device.deviceName + ' Fan', fanUuid);
      new TclFan(this, fanAccessory, device);
      this.api.registerPlatformAccessories('homebridge-tcl-home', 'TclHome', [fanAccessory]);
      this.accessories.push(fanAccessory);
    }
  }

  configureAccessory(accessory) {
    this.accessories.push(accessory);
  }
}

class TclHomeApi {
  constructor(config) {
    this.username = config.username;
    this.password = config.password;
    this.appLoginUrl = config.appLoginUrl;
    this.cloudUrls = config.cloudUrls;
    this.appId = config.appId;
    this.debugMode = config.debugMode;
    this.log = config.log;
    
    this.authData = null;
    this.cloudUrlsData = null;
    this.refreshTokensData = null;
    this.awsCredentials = null;
    this.currentDeviceState = {};
    this.iotData = null;
    this.authRetryCount = 0;
    this.maxAuthRetries = 3;
  }

  debug(message, ...args) {
    if (this.debugMode) {
      this.log.info(`[DEBUG] ${message}`, ...args);
    }
  }

  async initialize() {
    this.log.info('🔐 Authenticating with TCL Home...');
    await this.authenticate();
    await this.getCloudUrls();
    await this.refreshTokens();
    await this.getAwsCredentials();
    await this.setupAwsIot();
    this.log.info('✅ TCL API initialized successfully');
  }

  async authenticate() {
    const passwordHash = crypto.createHash('md5').update(this.password).digest('hex');
    
    const payload = {
      equipment: 2,
      password: passwordHash,
      osType: 1,
      username: this.username,
      clientVersion: "4.8.1",
      osVersion: "6.0",
      deviceModel: "AndroidAndroid SDK built for x86",
      captchaRule: 2,
      channel: "app"
    };

    const headers = {
      'th_platform': 'android',
      'th_version': '4.8.1',
      'th_appbulid': '830',
      'user-agent': 'Android',
      'content-type': 'application/json; charset=UTF-8'
    };

    try {
      const response = await axios.post(this.appLoginUrl, payload, { headers });
      
      if (response.data.status === 1) {
        this.authData = response.data;
        this.authRetryCount = 0; // Reset retry count on success
        this.log.info('✅ Successfully authenticated with TCL Home');
      } else {
        throw new Error('Authentication failed: Invalid credentials');
      }
    } catch (error) {
      throw new Error(`Authentication failed: ${error.message}`);
    }
  }

  async getCloudUrls() {
    const payload = {
      ssoId: this.authData.user.username,
      ssoToken: this.authData.token
    };

    const headers = {
      'user-agent': 'Android',
      'content-type': 'application/json; charset=UTF-8'
    };

    try {
      const response = await axios.post(this.cloudUrls, payload, { headers });
      this.cloudUrlsData = response.data;
    } catch (error) {
      throw new Error(`Failed to get cloud URLs: ${error.message}`);
    }
  }

  async refreshTokens() {
    const url = `${this.cloudUrlsData.data.cloud_url}/v3/auth/refresh_tokens`;
    
    const payload = {
      userId: this.authData.user.username,
      ssoToken: this.authData.token,
      appId: this.appId
    };

    const headers = {
      'user-agent': 'Android',
      'content-type': 'application/json; charset=UTF-8',
      'accept-encoding': 'gzip, deflate, br'
    };

    try {
      const response = await axios.post(url, payload, { headers });
      this.refreshTokensData = response.data;
    } catch (error) {
      throw new Error(`Failed to refresh tokens: ${error.message}`);
    }
  }

  async getAwsCredentials() {
    const region = this.cloudUrlsData.data.cloud_region;
    const url = `https://cognito-identity.${region}.amazonaws.com/`;
    
    const decoded = jwt.decode(this.refreshTokensData.data.cognitoToken, { complete: false });
    const identityId = decoded.sub;

    const payload = {
      IdentityId: identityId,
      Logins: {
        'cognito-identity.amazonaws.com': this.refreshTokensData.data.cognitoToken
      }
    };

    const headers = {
      'User-agent': 'aws-sdk-android/2.22.6 Linux/6.1.23-android14-4-00257-g7e35917775b8-ab9964412 Dalvik/2.1.0/0 en_US',
      'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
      'content-type': 'application/x-amz-json-1.1'
    };

    try {
      const response = await axios.post(url, payload, { headers });
      this.awsCredentials = response.data;
      this.log.info('✅ Got AWS credentials successfully');
    } catch (error) {
      this.log.error('❌ Failed to get AWS credentials:', error.message);
    }
  }

  async setupAwsIot() {
    try {
      const region = this.cloudUrlsData.data.cloud_region;
      
      AWS.config.update({
        accessKeyId: this.awsCredentials.Credentials.AccessKeyId,
        secretAccessKey: this.awsCredentials.Credentials.SecretKey,
        sessionToken: this.awsCredentials.Credentials.SessionToken,
        region: region
      });

      this.iotData = new AWS.IotData({
        endpoint: `https://data-ats.iot.${region}.amazonaws.com`
      });

      this.log.info('✅ AWS IoT Data client configured successfully');
    } catch (error) {
      this.log.error('❌ Failed to setup AWS IoT:', error.message);
    }
  }

  async getDevices() {
    const url = `${this.cloudUrlsData.data.device_url}/v3/user/get_things`;
    
    const timestamp = Date.now().toString();
    const nonce = Math.random().toString(36).substr(2, 16);
    const sign = this.calculateMd5Hash(timestamp + nonce + this.refreshTokensData.data.saasToken);

    const headers = {
      'platform': 'android',
      'appversion': '5.4.1',
      'thomeversion': '4.8.1',
      'accesstoken': this.refreshTokensData.data.saasToken,
      'countrycode': this.authData.user.countryAbbr,
      'accept-language': 'en',
      'timestamp': timestamp,
      'nonce': nonce,
      'sign': sign,
      'user-agent': 'Android',
      'content-type': 'application/json; charset=UTF-8',
      'accept-encoding': 'gzip, deflate, br'
    };

    try {
      const response = await axios.post(url, {}, { headers });
      return response.data.data || [];
    } catch (error) {
      throw new Error(`Failed to get devices: ${error.message}`);
    }
  }

  async getDeviceState(deviceId) {
    try {
      if (!this.iotData) {
        this.log.error('❌ AWS IoT Data client not initialized');
        return this.getFallbackDeviceState(deviceId);
      }

      const result = await this.iotData.getThingShadow({ thingName: deviceId }).promise();
      const shadowData = JSON.parse(result.payload.toString());
      
      if (shadowData && shadowData.state && shadowData.state.reported) {
        const reported = shadowData.state.reported;
        const desired = shadowData.state.desired || {};
        
        // Use targetCelsiusDegree instead of targetTemperature!
        const state = {
          powerSwitch: desired.powerSwitch !== undefined ? desired.powerSwitch : (reported.powerSwitch || 0),
          targetTemperature: desired.targetCelsiusDegree !== undefined ? desired.targetCelsiusDegree : (reported.targetCelsiusDegree || reported.targetTemperature || 24),
          currentTemperature: reported.currentTemperature || 22,
          workMode: desired.workMode !== undefined ? desired.workMode : (reported.workMode || 0),
          windSpeed: desired.windSpeed !== undefined ? desired.windSpeed : (reported.windSpeed || 1),
          sleep: desired.sleep !== undefined ? desired.sleep : (reported.sleep || 0),
          isOnline: true
        };
        
        this.currentDeviceState[deviceId] = state;
        this.debug(`📊 Real device shadow state for ${deviceId}:`, state);
        return state;
      }
    } catch (error) {
      this.debug('⚠️ Could not get device shadow, using fallback:', error.message);
    }
    
    return this.getFallbackDeviceState(deviceId);
  }

  getFallbackDeviceState(deviceId) {
    return this.currentDeviceState[deviceId] || {
      powerSwitch: 0,
      targetTemperature: 24,
      currentTemperature: 22,
      workMode: 0,
      windSpeed: 1,
      sleep: 0,
      isOnline: false
    };
  }

  async setDeviceState(deviceId, properties) {
    this.log.info(`🔧 REAL CONTROL: Setting device ${deviceId} properties:`, properties);
    
    try {
      const topic = `$aws/things/${deviceId}/shadow/update`;
      const payload = {
        state: {
          desired: properties
        },
        clientToken: `mobile_${Date.now()}`
      };

      this.debug(`Final AWS IoT payload: ${JSON.stringify(payload, null, 2)}`);

      const success = await this.publishToAwsIot(topic, JSON.stringify(payload));
      
      if (success) {
        if (!this.currentDeviceState[deviceId]) {
          this.currentDeviceState[deviceId] = {};
        }
        Object.assign(this.currentDeviceState[deviceId], properties);
        
        this.log.info(`✅ REAL CONTROL: Successfully sent command to device ${deviceId}`);
        return true;
      } else {
        this.log.error(`❌ REAL CONTROL: Failed to send command to device ${deviceId}`);
        return false;
      }
    } catch (error) {
      this.log.error('❌ Failed to set device state:', error.message);
      return false;
    }
  }

  async publishDeviceShadow(deviceId, payload) {
    const topic = `$aws/things/${deviceId}/shadow/update`;
    this.debug(`📡 Publishing custom payload to ${topic}`);
    await this.publishToAwsIot(topic, JSON.stringify(payload));
  }

  async publishToAwsIot(topic, payload) {
    try {
      if (!this.iotData) {
        this.log.error('❌ AWS IoT Data client not initialized');
        return false;
      }

      this.log.info(`📡 Publishing to AWS IoT topic: ${topic}`);
      this.debug(`📄 Payload: ${payload}`);

      const params = {
        topic: topic,
        payload: payload,
        qos: 1
      };

      const result = await this.iotData.publish(params).promise();
      this.log.info(`✅ Successfully published to AWS IoT`);
      return true;
    } catch (error) {
      if (error.message.includes('Forbidden')) {
        this.log.warn('🔄 AWS credentials expired, attempting to re-authenticate...');
        await this.handleAuthExpiry();
        return false;
      }
      this.log.error(`❌ Failed to publish to AWS IoT: ${error.message}`);
      return false;
    }
  }

  async handleAuthExpiry() {
    if (this.authRetryCount >= this.maxAuthRetries) {
      this.log.error('❌ Max authentication retries reached. Please restart Homebridge.');
      return;
    }

    this.authRetryCount++;
    this.log.info(`🔄 Re-authenticating (attempt ${this.authRetryCount}/${this.maxAuthRetries})...`);
    
    try {
      await this.initialize();
      this.log.info('✅ Re-authentication successful');
    } catch (error) {
      this.log.error('❌ Re-authentication failed:', error.message);
    }
  }

  calculateMd5Hash(input) {
    const hash = crypto.createHash('md5').update(input, 'utf8').digest();
    let hexString = '';
    for (let byte of hash) {
      const byteValue = byte & 0xFF;
      if (byteValue < 16) {
        hexString += '0';
      }
      hexString += byteValue.toString(16);
    }
    return hexString;
  }
}

class TclAirConditioner {
  constructor(platform, accessory, device) {
    this.platform = platform;
    this.accessory = accessory;
    this.device = device;
    this.log = platform.log;
    
    this.accessory.getService(this.platform.api.hap.Service.AccessoryInformation)
      .setCharacteristic(this.platform.api.hap.Characteristic.Manufacturer, 'TCL')
      .setCharacteristic(this.platform.api.hap.Characteristic.Model, 'P09F4CSW1K Portable AC')
      .setCharacteristic(this.platform.api.hap.Characteristic.SerialNumber, device.deviceId)
      .setCharacteristic(this.platform.api.hap.Characteristic.FirmwareRevision, device.firmwareVersion || '1.0.0');

    this.service = this.accessory.getService(this.platform.api.hap.Service.Thermostat) ||
                   this.accessory.addService(this.platform.api.hap.Service.Thermostat);

    this.service.setCharacteristic(this.platform.api.hap.Characteristic.Name, device.deviceName);

    this.sleepService = this.accessory.getService('Sleep Mode') ||
                       this.accessory.addService(this.platform.api.hap.Service.Switch, 'Sleep Mode', 'sleep');

    this.sleepService.getCharacteristic(this.platform.api.hap.Characteristic.On)
      .onGet(this.getSleepMode.bind(this))
      .onSet(this.setSleepMode.bind(this));

    this.setupCharacteristics();
    this.startPolling();
    
    this.log.info(`🏠 ${device.deviceName} ready for HomeKit!`);
  }

  setupCharacteristics() {
    const Characteristic = this.platform.api.hap.Characteristic;
    
    this.service.getCharacteristic(Characteristic.CurrentHeatingCoolingState)
      .onGet(this.getCurrentHeatingCoolingState.bind(this));

    this.service.getCharacteristic(Characteristic.TargetHeatingCoolingState)
      .onGet(this.getTargetHeatingCoolingState.bind(this))
      .onSet(this.setTargetHeatingCoolingState.bind(this))
      .setProps({
        validValues: [
          Characteristic.TargetHeatingCoolingState.OFF,   
          Characteristic.TargetHeatingCoolingState.COOL
          // Only OFF and COOL - no confusing AUTO mode
        ]
      });

    this.service.getCharacteristic(Characteristic.CurrentTemperature)
      .onGet(this.getCurrentTemperature.bind(this))
      .setProps({
        minValue: -50,
        maxValue: 100,
        minStep: 0.1
      });

    this.service.getCharacteristic(Characteristic.TargetTemperature)
      .onGet(this.getTargetTemperature.bind(this))
      .onSet(this.setTargetTemperature.bind(this))
      .setProps({
        minValue: 18,
        maxValue: 30,  
        minStep: 1
      });

    this.service.getCharacteristic(Characteristic.TemperatureDisplayUnits)
      .onGet(() => Characteristic.TemperatureDisplayUnits.CELSIUS);
  }

  async getCurrentHeatingCoolingState() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch || state.workMode === 3) {
        // OFF if device is off OR if in fan mode (fan accessory handles fan mode)
        return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
      }
      
      if (state.workMode === 0) {
        return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
      }
      
      return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
    } catch (error) {
      this.log.error('❌ Error getting current state:', error.message);
      return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
    }
  }

  async getTargetHeatingCoolingState() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch || state.workMode === 3) {
        // OFF if device is off OR if in fan mode
        return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
      }
      
      if (state.workMode === 0) {
        return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
      }
      
      return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
    } catch (error) {
      this.log.error('❌ Error getting target state:', error.message);
      return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
    }
  }

  async setTargetHeatingCoolingState(value) {
    try {
      const Characteristic = this.platform.api.hap.Characteristic;
      let properties = {};

      switch (value) {
        case Characteristic.TargetHeatingCoolingState.OFF:
          properties = { 
            powerSwitch: 0 
          };
          this.log.info(`❄️ AC: Setting to OFF`);
          break;
          
        case Characteristic.TargetHeatingCoolingState.COOL:
          properties = {
            powerSwitch: 1,
            workMode: 0,
            windSpeed: 0,
            ECO: 0,
            sleep: 0,
            turbo: 0,
            silenceSwitch: 0
          };
          this.log.info(`❄️ AC: Setting to COOL mode (AC cooling)`);
          break;
      }

      await this.platform.tclApi.setDeviceState(this.device.deviceId, properties);
      this.log.info(`🎯 AC: Set state to ${value}`);
    } catch (error) {
      this.log.error('❌ Error setting target state:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getCurrentTemperature() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      return state ? state.currentTemperature : 20;
    } catch (error) {
      this.log.error('❌ Error getting current temperature:', error.message);
      return 20;
    }
  }

  async getTargetTemperature() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (state && typeof state.targetTemperature === 'number') {
        this.platform.tclApi.debug(`🎯 AC: Reporting targetTemperature = ${state.targetTemperature}°C`);
        return state.targetTemperature;
      }
      return 24;
    } catch (error) {
      this.log.error('❌ Error getting target temperature:', error.message);
      return 24;
    }
  }

  async setTargetTemperature(value) {
    try {
      const temperature = Math.max(18, Math.min(30, Math.round(value)));

      const payload = {
        state: {
          desired: {
            targetCelsiusDegree: temperature
          }
        },
        clientToken: `mobile_${Date.now()}`
      };

      this.log.info(`🌡️ AC: Setting temperature to ${temperature}°C`);
      await this.platform.tclApi.publishDeviceShadow(this.device.deviceId, payload);

      // Update cache
      if (!this.platform.tclApi.currentDeviceState[this.device.deviceId]) {
        this.platform.tclApi.currentDeviceState[this.device.deviceId] = {};
      }
      this.platform.tclApi.currentDeviceState[this.device.deviceId].targetTemperature = temperature;

      // Force HomeKit update
      this.service.getCharacteristic(this.platform.api.hap.Characteristic.TargetTemperature).updateValue(temperature);

      this.log.info(`✅ AC: Temperature set to ${temperature}°C`);
    } catch (error) {
      this.log.error('❌ Error setting target temperature:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getSleepMode() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      return state ? (state.sleep === 1) : false;
    } catch (error) {
      this.log.error('❌ Error getting sleep mode:', error.message);
      return false;
    }
  }

  async setSleepMode(value) {
    try {
      const properties = {
        sleep: value ? 1 : 0
      };
      
      await this.platform.tclApi.setDeviceState(this.device.deviceId, properties);
      this.log.info(`😴 SLEEP MODE: ${value ? 'ON' : 'OFF'}`);
    } catch (error) {
      this.log.error('❌ Error setting sleep mode:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  startPolling() {
    setInterval(async () => {
      try {
        const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
        if (state) {
          // Update current temperature
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.CurrentTemperature,
            state.currentTemperature
          );

          // Update AC mode (only handles cooling, fan is separate)
          let currentHeatingCoolingState;
          let targetHeatingCoolingState;
          
          if (!state.powerSwitch || state.workMode === 3) {
            // OFF if device off OR in fan mode
            currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
            targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
          } else if (state.workMode === 0) {
            // Cooling mode
            currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
            targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
          } else {
            currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
            targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
          }

          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.CurrentHeatingCoolingState,
            currentHeatingCoolingState
          );
          
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            targetHeatingCoolingState
          );

          // Update sleep mode
          this.sleepService.updateCharacteristic(
            this.platform.api.hap.Characteristic.On,
            state.sleep === 1
          );
          
          this.platform.tclApi.debug(`🔄 AC Synced: Power=${state.powerSwitch}, Mode=${state.workMode}, Temp=${state.targetTemperature}°C`);
        }
      } catch (error) {
        this.platform.tclApi.debug('🔄 AC polling update:', error.message);
      }
    }, 15000);
  }
}

class TclFan {
  constructor(platform, accessory, device) {
    this.platform = platform;
    this.accessory = accessory;
    this.device = device;
    this.log = platform.log;
    
    this.accessory.getService(this.platform.api.hap.Service.AccessoryInformation)
      .setCharacteristic(this.platform.api.hap.Characteristic.Manufacturer, 'TCL')
      .setCharacteristic(this.platform.api.hap.Characteristic.Model, 'P09F4CSW1K Fan')
      .setCharacteristic(this.platform.api.hap.Characteristic.SerialNumber, device.deviceId + '-fan')
      .setCharacteristic(this.platform.api.hap.Characteristic.FirmwareRevision, device.firmwareVersion || '1.0.0');

    this.service = this.accessory.getService(this.platform.api.hap.Service.Fan) ||
                   this.accessory.addService(this.platform.api.hap.Service.Fan);

    this.service.setCharacteristic(this.platform.api.hap.Characteristic.Name, device.deviceName + ' Fan');

    this.service.getCharacteristic(this.platform.api.hap.Characteristic.On)
      .onGet(this.getFanOn.bind(this))
      .onSet(this.setFanOn.bind(this));

    this.service.getCharacteristic(this.platform.api.hap.Characteristic.RotationSpeed)
      .onGet(this.getRotationSpeed.bind(this))
      .onSet(this.setRotationSpeed.bind(this))
      .setProps({
        minValue: 0,
        maxValue: 100,
        minStep: 1
      });

    this.startPolling();
    
    this.log.info(`💨 ${device.deviceName} Fan ready for HomeKit!`);
  }

  async getFanOn() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      return state ? (state.powerSwitch === 1 && state.workMode === 3) : false;
    } catch (error) {
      this.log.error('❌ Error getting fan state:', error.message);
      return false;
    }
  }

  async setFanOn(value) {
    try {
      if (value) {
        // Turn on fan mode
        const properties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: 1  // Default to F1
        };
        await this.platform.tclApi.setDeviceState(this.device.deviceId, properties);
        this.log.info(`💨 FAN: Turned ON (fan mode activated)`);
      } else {
        // Turn off everything
        const properties = {
          powerSwitch: 0
        };
        await this.platform.tclApi.setDeviceState(this.device.deviceId, properties);
        this.log.info(`💨 FAN: Turned OFF (device off)`);
      }
    } catch (error) {
      this.log.error('❌ Error setting fan state:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getRotationSpeed() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || state.workMode !== 3) {
        return 0; // Fan is off if not in fan mode
      }
      
      // FIXED MAPPING: F1=50%, F2=100%
      switch (state.windSpeed) {
        case 1: return 50;   // F1 = 50% in HomeKit
        case 2: return 100;  // F2 = 100% in HomeKit  
        default: return 50;
      }
    } catch (error) {
      this.log.error('❌ Error getting fan rotation speed:', error.message);
      return 50;
    }
  }

  async setRotationSpeed(value) {
    try {
      // Ensure we're in fan mode first
      const currentState = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      
      if (!currentState || currentState.workMode !== 3) {
        // Switch to fan mode first
        this.log.info(`💨 FAN: Switching to fan mode for speed adjustment`);
        const modeProperties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: 1
        };
        await this.platform.tclApi.setDeviceState(this.device.deviceId, modeProperties);
        // Wait a moment for mode switch
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // FIXED MAPPING: 1-50% = F1, 51-100% = F2
      let fanSpeed;
      let fanName;
      
      if (value <= 50) {
        fanSpeed = 1;  // F1 (Low)
        fanName = 'F1 (Low)';
      } else {
        fanSpeed = 2;  // F2 (High)
        fanName = 'F2 (High)';
      }
      
      const properties = {
        windSpeed: fanSpeed
      };
      
      await this.platform.tclApi.setDeviceState(this.device.deviceId, properties);
      this.log.info(`💨 FAN SPEED: Set to ${fanName} (${value}% in HomeKit)`);
    } catch (error) {
      this.log.error('❌ Error setting fan rotation speed:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  startPolling() {
    setInterval(async () => {
      try {
        const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
        if (state) {
          // Update fan on/off state
          const isFanMode = state.workMode === 3;
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.On,
            state.powerSwitch === 1 && isFanMode
          );

          // Update fan speed
          let fanSpeedPercent = 0;
          if (isFanMode) {
            switch (state.windSpeed) {
              case 1: fanSpeedPercent = 50; break;   // F1 = 50%
              case 2: fanSpeedPercent = 100; break;  // F2 = 100%
              default: fanSpeedPercent = 50; break;
            }
          }
          
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.RotationSpeed,
            fanSpeedPercent
          );
          
          this.platform.tclApi.debug(`🔄 FAN Synced: Power=${state.powerSwitch}, Mode=${state.workMode}, Speed=${fanSpeedPercent}%`);
        }
      } catch (error) {
        this.platform.tclApi.debug('🔄 Fan polling update:', error.message);
      }
    }, 15000);
  }
}
