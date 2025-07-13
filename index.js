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
    const existingAccessory = this.accessories.find(acc => acc.UUID === uuid);

    if (existingAccessory) {
      this.log.info('🔄 Updating existing accessory:', device.deviceName);
      new TclAirConditioner(this, existingAccessory, device);
    } else {
      this.log.info('🆕 Adding new accessory:', device.deviceName);
      const accessory = new this.api.platformAccessory(device.deviceName, uuid);
      new TclAirConditioner(this, accessory, device);
      this.api.registerPlatformAccessories('homebridge-tcl-home', 'TclHome', [accessory]);
      this.accessories.push(accessory);
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
        this.authRetryCount = 0;
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
        this.debug('❌ AWS IoT Data client not initialized');
        return this.getFallbackDeviceState(deviceId);
      }

      const result = await this.iotData.getThingShadow({ thingName: deviceId }).promise();
      const shadowData = JSON.parse(result.payload.toString());
      
      if (shadowData && shadowData.state && shadowData.state.reported) {
        const reported = shadowData.state.reported;
        const desired = shadowData.state.desired || {};
        
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
      targetTemperature: 18,
      currentTemperature: 22,
      workMode: 0,
      windSpeed: 2,
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
    
    this.consecutiveErrors = 0;
    this.lastSuccessfulPoll = Date.now();
    
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

    this.fanService = this.accessory.getService('Fan Speed') ||
                     this.accessory.addService(this.platform.api.hap.Service.Fan, 'Fan Speed', 'fan');

    this.fanService.getCharacteristic(this.platform.api.hap.Characteristic.On)
      .onGet(this.getFanOn.bind(this))
      .onSet(this.setFanOn.bind(this));

    this.fanService.getCharacteristic(this.platform.api.hap.Characteristic.RotationSpeed)
      .onGet(this.getRotationSpeed.bind(this))
      .onSet(this.setRotationSpeed.bind(this))
      .setProps({
        minValue: 0,
        maxValue: 100,
        minStep: 1
      });

    this.setupCharacteristics();
    this.startPolling();
    
    this.platform.tclApi.debug(`🔍 ${device.deviceName} constructor complete, starting diagnostics...`);
    
    setTimeout(() => {
      this.platform.tclApi.debug(`🕐 10 seconds elapsed - checking connection status...`);
      this.checkConnectionStatus();
    }, 10000);
    
    this.log.info(`🏠 ${device.deviceName} ready for HomeKit! (Combined AC + Fan)`);
  }

  async checkConnectionStatus() {
    try {
      this.platform.tclApi.debug(`🔍 Connection Check:`);
      this.platform.tclApi.debug(`   - AWS IoT Data: ${this.platform.tclApi.iotData ? 'Connected' : 'NOT CONNECTED'}`);
      this.platform.tclApi.debug(`   - Last successful poll: ${this.lastSuccessfulPoll ? new Date(this.lastSuccessfulPoll).toLocaleTimeString() : 'NEVER'}`);
      this.platform.tclApi.debug(`   - Consecutive errors: ${this.consecutiveErrors}`);
      
      this.platform.tclApi.debug(`🔄 Attempting multiple state fetches to get real device state...`);
      
      for (let attempt = 1; attempt <= 3; attempt++) {
        this.platform.tclApi.debug(`   📡 Fetch attempt ${attempt}/3...`);
        
        try {
          const result = await this.platform.tclApi.iotData.getThingShadow({ 
            thingName: this.device.deviceId 
          }).promise();
          
          const shadowData = JSON.parse(result.payload.toString());
          this.platform.tclApi.debug(`   📊 Raw shadow data attempt ${attempt}: ${JSON.stringify(shadowData, null, 2)}`);
          
          if (shadowData && shadowData.state) {
            const reported = shadowData.state.reported || {};
            const desired = shadowData.state.desired || {};
            
            this.platform.tclApi.debug(`   📊 Reported state: ${JSON.stringify(reported, null, 2)}`);
            this.platform.tclApi.debug(`   📊 Desired state: ${JSON.stringify(desired, null, 2)}`);
            
            const freshState = {
              powerSwitch: desired.powerSwitch !== undefined ? desired.powerSwitch : (reported.powerSwitch || 0),
              targetTemperature: desired.targetCelsiusDegree !== undefined ? desired.targetCelsiusDegree : (reported.targetCelsiusDegree || reported.targetTemperature || 24),
              currentTemperature: reported.currentTemperature || 22,
              workMode: desired.workMode !== undefined ? desired.workMode : (reported.workMode || 0),
              windSpeed: desired.windSpeed !== undefined ? desired.windSpeed : (reported.windSpeed || 0),
              sleep: desired.sleep !== undefined ? desired.sleep : (reported.sleep || 0),
              isOnline: true
            };
            
            this.platform.tclApi.debug(`   ✅ Fresh state attempt ${attempt}: power=${freshState.powerSwitch}, mode=${freshState.workMode}, windSpeed=${freshState.windSpeed}`);
            
            if (freshState.workMode !== 2 || freshState.windSpeed !== 0) {
              this.platform.tclApi.debug(`   🎯 Found different state on attempt ${attempt}! Using this one.`);
              await this.updateHomeKitWithState(freshState);
              return;
            }
          }
          
          if (attempt < 3) {
            await new Promise(resolve => setTimeout(resolve, 2000));
          }
          
        } catch (error) {
          this.platform.tclApi.debug(`   ❌ Fetch attempt ${attempt} failed: ${error.message}`);
        }
      }
      
      this.platform.tclApi.debug(`⚠️ All fetch attempts returned the same state - this might be correct`);
      this.platform.tclApi.debug(`⚠️ Your AC might actually be in mode 2 with windSpeed 0`);
      this.platform.tclApi.debug(`⚠️ Try checking the actual AC unit - what mode/speed does it show?`);
      
    } catch (error) {
      this.platform.tclApi.debug(`❌ Connection check failed: ${error.message}`);
    }
  }

  async updateHomeKitWithState(state) {
    this.platform.tclApi.debug(`🔄 Updating HomeKit with fresh state...`);
    
    this.service.updateCharacteristic(
      this.platform.api.hap.Characteristic.CurrentTemperature,
      state.currentTemperature
    );
    
    if (state.powerSwitch === 1) {
      if (state.workMode === 0) {
        this.service.updateCharacteristic(
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL
        );
        this.log.info(`✅ Updated: AC COOL mode`);
      } else if (state.workMode === 2) {
        this.service.updateCharacteristic(
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
        );
        this.log.info(`✅ Updated: Fan AUTO mode (Mode 2 - sync issue)`);
        
        this.fanService.updateCharacteristic(
          this.platform.api.hap.Characteristic.On,
          true
        );
        
        let fanPercent = 50; // CHANGED: Default to 50% for windSpeed 0
        switch (state.windSpeed) {
          case 1: fanPercent = 100; break;
          case 2: fanPercent = 50; break;
          case 0: fanPercent = 50; break; // CHANGED: 50% fallback
          default: fanPercent = 50; break;
        }
        
        this.fanService.updateCharacteristic(
          this.platform.api.hap.Characteristic.RotationSpeed,
          fanPercent
        );
        
        this.log.info(`✅ Updated: Fan ON at ${fanPercent}% (windSpeed=${state.windSpeed}, F2 assumed due to sync)`);
      } else if (state.workMode === 3) {
        this.service.updateCharacteristic(
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
          this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
        );
        this.log.info(`✅ Updated: FAN mode`);
        
        this.fanService.updateCharacteristic(
          this.platform.api.hap.Characteristic.On,
          true
        );
        
        let fanPercent = 50; // Default
        switch (state.windSpeed) {
          case 1: fanPercent = 100; break;
          case 2: fanPercent = 50; break;
          case 0: fanPercent = 50; break; // CHANGED: 50% fallback
          default: fanPercent = 50; break;
        }
        
        this.fanService.updateCharacteristic(
          this.platform.api.hap.Characteristic.RotationSpeed,
          fanPercent
        );
        
        this.log.info(`✅ Updated: Fan ON at ${fanPercent}% (windSpeed=${state.windSpeed})`);
      } else {
        this.platform.tclApi.debug(`⚠️ Unknown mode ${state.workMode} - treating as OFF`);
      }
    } else {
      this.service.updateCharacteristic(
        this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
        this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF
      );
      this.log.info(`✅ Updated: OFF`);
    }
  }

  async executeWithAWSRetry(operation, context = '') {
    try {
      return await operation();
    } catch (error) {
      if (error.message.includes('Forbidden') || 
          error.message.includes('Credentials') || 
          error.message.includes('expired') ||
          error.message.includes('InvalidToken')) {
        this.log.warn(`🔄 AWS error in ${context}, re-authenticating...`);
        await this.platform.tclApi.handleAuthExpiry();
        
        try {
          return await operation();
        } catch (retryError) {
          this.log.error(`❌ ${context} failed even after re-auth:`, retryError.message);
          throw retryError;
        }
      }
      throw error;
    }
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
          Characteristic.TargetHeatingCoolingState.COOL,  
          Characteristic.TargetHeatingCoolingState.AUTO   
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

  enableTemperatureControl() {
    this.service.getCharacteristic(this.platform.api.hap.Characteristic.TargetTemperature)
      .setProps({
        minValue: 18,
        maxValue: 30,
        minStep: 1,
        perms: [
          this.platform.api.hap.Characteristic.Perms.READ,
          this.platform.api.hap.Characteristic.Perms.WRITE,
          this.platform.api.hap.Characteristic.Perms.NOTIFY
        ]
      });
    this.platform.tclApi.debug('🌡️ Temperature control enabled');
  }

  disableTemperatureControl() {
    this.service.getCharacteristic(this.platform.api.hap.Characteristic.TargetTemperature)
      .setProps({
        minValue: 18,
        maxValue: 30,
        minStep: 1,
        perms: [
          this.platform.api.hap.Characteristic.Perms.READ,
          this.platform.api.hap.Characteristic.Perms.NOTIFY
        ]
      });
    this.platform.tclApi.debug('🌡️ Temperature control disabled (fan mode)');
  }

  async getCurrentHeatingCoolingState() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch) {
        return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
      }
      
      switch (state.workMode) {
        case 0:
          return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
        case 2:
        case 3:
          return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
        default:
          return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
      }
    } catch (error) {
      this.log.error('❌ Error getting current state:', error.message);
      return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
    }
  }

  async getTargetHeatingCoolingState() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch) {
        return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
      }
      
      switch (state.workMode) {
        case 0:
          return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
        case 2:
        case 3:
          return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO;
        default:
          return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
      }
    } catch (error) {
      this.log.error('❌ Error getting target state:', error.message);
      return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
    }
  }

  async setTargetHeatingCoolingState(value) {
    try {
      const Characteristic = this.platform.api.hap.Characteristic;
      let properties = {};

      this.lastModeChange = Date.now();
      this.lockedMode = value;

      switch (value) {
        case Characteristic.TargetHeatingCoolingState.OFF:
          properties = { 
            powerSwitch: 0 
          };
          this.log.info(`❄️ Setting AC to OFF`);
          setTimeout(() => this.enableTemperatureControl(), 500);
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
          this.log.info(`❄️ Setting AC to COOL mode (AC cooling)`);
          setTimeout(() => this.enableTemperatureControl(), 500);
          break;
          
        case Characteristic.TargetHeatingCoolingState.AUTO:
          properties = {
            powerSwitch: 1,
            workMode: 3,
            windSpeed: 2
          };
          this.log.info(`💨 Setting AC to AUTO mode (Fan only) - LOCKED permanently`);
          setTimeout(() => this.disableTemperatureControl(), 500);
          break;
      }

      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setTargetHeatingCoolingState'
      );
      this.log.info(`🎯 Set heating/cooling state to ${value} - mode LOCKED until manually changed`);
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
        this.platform.tclApi.debug(`🎯 Reporting targetTemperature = ${state.targetTemperature}°C`);
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

      this.log.info(`🌡️ Setting temperature to ${temperature}°C`);
      await this.executeWithAWSRetry(
        () => this.platform.tclApi.publishDeviceShadow(this.device.deviceId, payload),
        'setTargetTemperature'
      );

      if (!this.platform.tclApi.currentDeviceState[this.device.deviceId]) {
        this.platform.tclApi.currentDeviceState[this.device.deviceId] = {};
      }
      this.platform.tclApi.currentDeviceState[this.device.deviceId].targetTemperature = temperature;

      this.service.getCharacteristic(this.platform.api.hap.Characteristic.TargetTemperature).updateValue(temperature);

      this.log.info(`✅ Temperature set to ${temperature}°C`);
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
      
      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setSleepMode'
      );
      this.log.info(`😴 SLEEP MODE: ${value ? 'ON' : 'OFF'}`);
    } catch (error) {
      this.log.error('❌ Error setting sleep mode:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getFanOn() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      
      if (this.lockedMode === this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO && state && state.powerSwitch === 1) {
        return true;
      }
      
      return state ? (state.powerSwitch === 1 && (state.workMode === 3 || state.workMode === 2)) : false;
    } catch (error) {
      this.log.error('❌ Error getting fan state:', error.message);
      return false;
    }
  }

  async setFanOn(value) {
    try {
      this.lastModeChange = Date.now();
      
      if (value) {
        this.lockedMode = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO;
        this.log.info(`💨 FAN: Turning ON - switching to AUTO mode`);
        const properties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: 2
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setFanOn'
        );
        
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
          );
          this.disableTemperatureControl();
        }, 500);
        
        this.log.info(`💨 FAN: ON (AUTO mode activated - LOCKED permanently)`);
      } else {
        this.lockedMode = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
        const properties = {
          powerSwitch: 0
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setFanOff'
        );
        
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF
          );
          this.enableTemperatureControl();
        }, 500);
        
        this.log.info(`💨 FAN: OFF (device off)`);
      }
    } catch (error) {
      this.log.error('❌ Error setting fan state:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getRotationSpeed() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch) {
        return 0;
      }
      
      // If we're locked to AUTO mode, always show fan speed
      if (this.lockedMode === this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO) {
        if (this.lastUserSetSpeed !== undefined) {
          return this.lastUserSetSpeed;
        }
        
        // Handle windSpeed mapping
        switch (state.windSpeed) {
          case 1: return 100;  // F1 = 100%
          case 2: return 50;   // F2 = 50%
          case 0: return 50;   // CHANGED: windSpeed 0 = 50% (F2 equivalent)
          default: return 50;
        }
      }
      
      // Handle Mode 2 + Mode 3 as fan modes
      if (state.workMode !== 3 && state.workMode !== 2) {
        return 0; // Not in fan mode
      }
      
      if (this.lastUserSetSpeed !== undefined) {
        return this.lastUserSetSpeed;
      }
      
      // Handle windSpeed 0 in fan modes
      switch (state.windSpeed) {
        case 1: return 100;  // F1 = 100%
        case 2: return 50;   // F2 = 50%
        case 0: 
          // CHANGED: windSpeed 0 but in fan mode = assume F2 (50% speed)
          this.platform.tclApi.debug(`💨 Fan mode with windSpeed=0 - assuming F2 (50%) due to sync issue`);
          return 50;
        default: return 50;
      }
    } catch (error) {
      this.log.error('❌ Error getting fan rotation speed:', error.message);
      return 50; // CHANGED: Safe fallback to 50%
    }
  }

  async setRotationSpeed(value) {
    try {
      this.lastModeChange = Date.now();
      this.lastUserSetSpeed = value;
      
      const currentState = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      
      if (!currentState || (currentState.workMode !== 3 && currentState.workMode !== 2)) {
        this.lockedMode = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO;
        this.log.info(`💨 FAN SPEED: Auto-switching to fan mode`);
        const modeProperties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: 2
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, modeProperties),
          'setRotationSpeed-autoSwitch'
        );
        
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
          );
          this.disableTemperatureControl();
        }, 500);
        
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      let fanSpeed;
      let fanName;
      
      if (value <= 50) {
        fanSpeed = 2;
        fanName = 'F2 (Low)';
      } else {
        fanSpeed = 1;
        fanName = 'F1 (High)';
      }
      
      const properties = {
        windSpeed: fanSpeed
      };
      
      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setRotationSpeed'
      );
      this.log.info(`💨 FAN SPEED: Set to ${fanName} (${value}% → hardware F${fanSpeed}) - USER SET ${value}% - AUTO mode LOCKED permanently`);
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
          this.consecutiveErrors = 0;
          this.lastSuccessfulPoll = Date.now();
          
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.CurrentTemperature,
            state.currentTemperature
          );

          if (this.lockedMode !== undefined) {
            this.service.updateCharacteristic(
              this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
              this.lockedMode
            );
            
            let currentState;
            if (!state.powerSwitch) {
              currentState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
            } else {
              currentState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
            }
            
            this.service.updateCharacteristic(
              this.platform.api.hap.Characteristic.CurrentHeatingCoolingState,
              currentState
            );
            
            this.platform.tclApi.debug(`🔒 Mode LOCKED: Target=${this.lockedMode}, Current=COOL (HomeKit design), Device: Power=${state.powerSwitch}, Mode=${state.workMode}`);
          } else {
            let currentHeatingCoolingState;
            let targetHeatingCoolingState;
            
            if (!state.powerSwitch) {
              currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
              targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
            } else {
              switch (state.workMode) {
                case 0:
                  currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
                  targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
                  break;
                case 2:
                case 3:
                  currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
                  targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO;
                  break;
                default:
                  currentHeatingCoolingState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
                  targetHeatingCoolingState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
                  break;
              }
            }

            this.service.updateCharacteristic(
              this.platform.api.hap.Characteristic.CurrentHeatingCoolingState,
              currentHeatingCoolingState
            );
            
            this.service.updateCharacteristic(
              this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
              targetHeatingCoolingState
            );
          }

          if (state.workMode === 3 || state.workMode === 2 || this.lockedMode === this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO) {
            this.disableTemperatureControl();
          } else {
            this.enableTemperatureControl();
          }

          this.sleepService.updateCharacteristic(
            this.platform.api.hap.Characteristic.On,
            state.sleep === 1
          );

          let isFanMode = false;
          let fanSpeedPercent = 0;

          if (this.lockedMode === this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO && state.powerSwitch === 1) {
            isFanMode = true;
            
            if (this.lastUserSetSpeed !== undefined) {
              fanSpeedPercent = this.lastUserSetSpeed;
            } else {
              switch (state.windSpeed) {
                case 1: fanSpeedPercent = 100; break;
                case 2: fanSpeedPercent = 50; break;
                case 0: fanSpeedPercent = 50; break; // CHANGED: 50% fallback
                default: fanSpeedPercent = 50; break;
              }
            }
          } else if (state.workMode === 3 || state.workMode === 2) {
            isFanMode = true;
            
            if (this.lastUserSetSpeed !== undefined) {
              fanSpeedPercent = this.lastUserSetSpeed;
            } else {
              switch (state.windSpeed) {
                case 1: fanSpeedPercent = 100; break;
                case 2: fanSpeedPercent = 50; break;
                case 0: 
                  fanSpeedPercent = 50;
                  this.platform.tclApi.debug(`💨 Fan mode ${state.workMode} with windSpeed=0, assuming F2 (50%)`);
                  break;
                default: fanSpeedPercent = 50; break;
              }
            }
          }
          
          this.fanService.updateCharacteristic(
            this.platform.api.hap.Characteristic.On,
            state.powerSwitch === 1 && isFanMode
          );
          
          this.fanService.updateCharacteristic(
            this.platform.api.hap.Characteristic.RotationSpeed,
            fanSpeedPercent
          );
          
          this.platform.tclApi.debug(`🔄 Synced: Power=${state.powerSwitch}, DeviceMode=${state.workMode}, LockedMode=${this.lockedMode}, Fan=${fanSpeedPercent}%`);
        }
      } catch (error) {
        this.platform.tclApi.debug('🔄 Polling update:', error.message);
        
        this.consecutiveErrors++;
        
        if (error.message.includes('Forbidden') || 
            error.message.includes('Credentials') || 
            error.message.includes('expired') ||
            error.message.includes('InvalidToken')) {
          this.log.warn('🔄 AWS credentials issue detected, re-authenticating...');
          await this.platform.tclApi.handleAuthExpiry();
          this.consecutiveErrors = 0;
          return;
        }
        
        if (this.consecutiveErrors >= 3) {
          this.log.warn(`🔄 ${this.consecutiveErrors} consecutive failures detected, triggering re-authentication`);
          await this.platform.tclApi.handleAuthExpiry();
          this.consecutiveErrors = 0;
        }
        
        const timeSinceLastSuccess = Date.now() - this.lastSuccessfulPoll;
        if (timeSinceLastSuccess > 60000) {
          this.platform.tclApi.debug(`🔌 Connection degraded: ${Math.round(timeSinceLastSuccess/1000)}s since last successful poll`);
        }
      }
    }, 8000);
  }
}
