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
    
    // REMOVED: No separate fan accessory creation - everything is unified now
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
    this.iotClient = null;
    this.subscriptions = new Map();
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

      this.iotClient = new AWS.Iot({
        endpoint: `https://iot.${region}.amazonaws.com`
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

      await this.iotData.publish(params).promise();
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

  async subscribeToDeviceUpdates(deviceId, callback) {
    try {
      // Clean up existing subscription if any
      if (this.subscriptions.has(deviceId)) {
        const existingClient = this.subscriptions.get(deviceId);
        existingClient.end(true);
        this.subscriptions.delete(deviceId);
      }
      
      const mqtt = require('mqtt');
      
      const region = this.cloudUrlsData.data.cloud_region;
      const endpoint = `wss://data-ats.iot.${region}.amazonaws.com/mqtt`;
      
      // Create signed WebSocket URL for AWS IoT Core
      const signedUrl = this.createSignedWebSocketUrl(endpoint, region);
      
      const client = mqtt.connect(signedUrl, {
        clientId: `homebridge_${deviceId}_${Date.now()}`,
        protocolVersion: 4,
        clean: true,
        reconnectPeriod: 5000,
        keepalive: 60
      });

      const topic = `$aws/things/${deviceId}/shadow/update/delta`;
      const shadowTopic = `$aws/things/${deviceId}/shadow/update/accepted`;
      
      client.on('connect', () => {
        this.log.info(`📡 Connected to AWS IoT for live updates: ${deviceId}`);
        client.subscribe([topic, shadowTopic], (err) => {
          if (err) {
            this.log.error('❌ Failed to subscribe to shadow updates:', err.message);
          } else {
            this.log.info('✅ Subscribed to device shadow updates');
          }
        });
      });

      client.on('message', (receivedTopic, message) => {
        try {
          const data = JSON.parse(message.toString());
          this.debug(`📨 Live update from ${deviceId}:`, data);
          
          if (receivedTopic === shadowTopic && data.state && data.state.reported) {
            // Update our cache with live data
            this.currentDeviceState[deviceId] = {
              ...this.currentDeviceState[deviceId],
              ...data.state.reported,
              targetTemperature: data.state.reported.targetCelsiusDegree || data.state.reported.targetTemperature,
              isOnline: true
            };
            callback(this.currentDeviceState[deviceId]);
          }
        } catch (error) {
          this.debug('Error parsing IoT message:', error.message);
        }
      });

      client.on('error', (error) => {
        this.log.warn('🔌 AWS IoT connection error:', error.message);
      });

      client.on('close', () => {
        this.log.warn('🔌 AWS IoT connection closed, will attempt reconnect');
      });
      
      client.on('reconnect', () => {
        this.log.info('🔄 AWS IoT reconnecting...');
      });

      this.subscriptions.set(deviceId, client);
      return client;
      
    } catch (error) {
      this.log.error('❌ Failed to setup IoT subscription:', error.message);
      return null;
    }
  }

  createSignedWebSocketUrl(endpoint, region) {
    const crypto = require('crypto');
    
    const credentials = this.awsCredentials.Credentials;
    const accessKey = credentials.AccessKeyId;
    const secretKey = credentials.SecretKey;
    const sessionToken = credentials.SessionToken;
    
    const date = new Date();
    const dateStamp = date.toISOString().slice(0, 10).replace(/-/g, '');
    const amzDate = date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
    
    const algorithm = 'AWS4-HMAC-SHA256';
    const service = 'iotdevicegateway';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    
    const canonicalQuerystring = [
      `X-Amz-Algorithm=${algorithm}`,
      `X-Amz-Credential=${encodeURIComponent(accessKey + '/' + credentialScope)}`,
      `X-Amz-Date=${amzDate}`,
      `X-Amz-SignedHeaders=host`,
      `X-Amz-Security-Token=${encodeURIComponent(sessionToken)}`
    ].join('&');
    
    const host = endpoint.replace('wss://', '').replace('/mqtt', '');
    const canonicalRequest = [
      'GET',
      '/mqtt',
      canonicalQuerystring,
      `host:${host}`,
      '',
      'host',
      crypto.createHash('sha256').update('').digest('hex')
    ].join('\n');
    
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      crypto.createHash('sha256').update(canonicalRequest).digest('hex')
    ].join('\n');
    
    const signingKey = this.getSignatureKey(secretKey, dateStamp, region, service);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    
    return `${endpoint}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
  }
  
  getSignatureKey(key, dateStamp, regionName, serviceName) {
    const crypto = require('crypto');
    const kDate = crypto.createHmac('sha256', 'AWS4' + key).update(dateStamp).digest();
    const kRegion = crypto.createHmac('sha256', kDate).update(regionName).digest();
    const kService = crypto.createHmac('sha256', kRegion).update(serviceName).digest();
    return crypto.createHmac('sha256', kService).update('aws4_request').digest();
  }
  
  cleanup() {
    // Clean up all MQTT subscriptions
    for (const [deviceId, client] of this.subscriptions) {
      try {
        client.end(true);
        this.log.info(`🧹 Cleaned up IoT subscription for ${deviceId}`);
      } catch (error) {
        this.log.warn(`⚠️ Error cleaning up subscription for ${deviceId}:`, error.message);
      }
    }
    this.subscriptions.clear();
  }
}

class TclAirConditioner {
  constructor(platform, accessory, device) {
    this.platform = platform;
    this.accessory = accessory;
    this.device = device;
    this.log = platform.log;
    
    // Live update tracking
    this.lastDeviceUpdate = 0;
    this.pendingUpdates = false;
    
    // Separate fan speed contexts
    this.coolModeFanSpeed = 1; // F1 for cool mode
    this.fanModeFanSpeed = 2;  // F2 for fan mode
    
    // AWS Error Recovery & Connection Health Monitoring
    this.consecutiveErrors = 0;  // Track connection health
    this.lastSuccessfulPoll = Date.now();  // Track last successful poll
    
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

    // Remove old services if they exist with wrong subtypes
    const oldFanService = this.accessory.getService('Fan Speed');
    if (oldFanService) {
      this.accessory.removeService(oldFanService);
    }

    // Fan mode controls (Auto mode)
    this.fanService = this.accessory.getService('Fan Mode') ||
                     this.accessory.addService(this.platform.api.hap.Service.Fan, 'Fan Mode', 'fanMode');

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

    // Cool mode fan controls (separate from Fan mode)
    this.coolFanService = this.accessory.getService('Cool Fan Speed') ||
                         this.accessory.addService(this.platform.api.hap.Service.Fan, 'Cool Fan Speed', 'coolFanSpeed');

    this.coolFanService.getCharacteristic(this.platform.api.hap.Characteristic.On)
      .onGet(this.getCoolFanOn.bind(this))
      .onSet(this.setCoolFanOn.bind(this));

    this.coolFanService.getCharacteristic(this.platform.api.hap.Characteristic.RotationSpeed)
      .onGet(this.getCoolFanSpeed.bind(this))
      .onSet(this.setCoolFanSpeed.bind(this))
      .setProps({
        minValue: 0,
        maxValue: 100,
        minStep: 1
      });

    this.setupCharacteristics();
    this.setupLiveUpdates();
    this.startPolling(); // Keep as backup but reduce frequency
    
    this.log.info(`🏠 ${device.deviceName} ready for HomeKit! (Live updates + Separate Fan Controls)`);
  }

  async setupLiveUpdates() {
    try {
      await this.platform.tclApi.subscribeToDeviceUpdates(
        this.device.deviceId, 
        (state) => this.handleLiveUpdate(state)
      );
      this.log.info(`📡 Live updates enabled for ${this.device.deviceName}`);
    } catch (error) {
      this.log.warn('⚠️ Could not setup live updates, using polling fallback:', error.message);
    }
  }
  
  handleLiveUpdate(state) {
    try {
      this.lastDeviceUpdate = Date.now();
      this.log.info(`📨 Live update: Power=${state.powerSwitch}, Mode=${state.workMode}, WindSpeed=${state.windSpeed}`);
      
      // Update HomeKit characteristics immediately
      this.updateHomeKitFromState(state);
      
    } catch (error) {
      this.log.error('❌ Error handling live update:', error.message);
    }
  }
  
  updateHomeKitFromState(state) {
    // Update current temperature
    this.service.updateCharacteristic(
      this.platform.api.hap.Characteristic.CurrentTemperature,
      state.currentTemperature || 22
    );
    
    // Update target temperature if it changed
    if (state.targetTemperature) {
      this.service.updateCharacteristic(
        this.platform.api.hap.Characteristic.TargetTemperature,
        state.targetTemperature
      );
    }
    
    // Update heating/cooling states
    let currentState, targetState;
    
    if (!state.powerSwitch) {
      currentState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.OFF;
      targetState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
    } else {
      currentState = this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
      
      switch (state.workMode) {
        case 0: // Cool mode
        case 2: // Another cool mode variant
          targetState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
          this.enableTemperatureControl();
          break;
        case 3: // Fan mode
          targetState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO;
          this.disableTemperatureControl();
          break;
        default:
          targetState = this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF;
          break;
      }
    }
    
    this.service.updateCharacteristic(
      this.platform.api.hap.Characteristic.CurrentHeatingCoolingState,
      currentState
    );
    
    this.service.updateCharacteristic(
      this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
      targetState
    );
    
    // Update sleep mode
    this.sleepService.updateCharacteristic(
      this.platform.api.hap.Characteristic.On,
      state.sleep === 1
    );
    
    // Update fan mode controls (Auto mode)
    const isFanOn = state.powerSwitch === 1 && state.workMode === 3;
    this.fanService.updateCharacteristic(
      this.platform.api.hap.Characteristic.On,
      isFanOn
    );
    
    if (isFanOn) {
      // Fan mode speeds: F1=100%, F2=50%
      const fanSpeed = state.windSpeed === 1 ? 100 : 50;
      this.fanService.updateCharacteristic(
        this.platform.api.hap.Characteristic.RotationSpeed,
        fanSpeed
      );
      
      // Store current fan mode speed
      this.fanModeFanSpeed = state.windSpeed;
    } else {
      this.fanService.updateCharacteristic(
        this.platform.api.hap.Characteristic.RotationSpeed,
        0
      );
    }
    
    // Update cool fan controls (Cool mode)
    const isCoolFanOn = state.powerSwitch === 1 && (state.workMode === 0 || state.workMode === 2);
    this.coolFanService.updateCharacteristic(
      this.platform.api.hap.Characteristic.On,
      isCoolFanOn
    );
    
    if (isCoolFanOn) {
      // Cool mode speeds: F1=100%, F2/Auto=50%
      const coolFanSpeed = state.windSpeed === 1 ? 100 : 50;
      this.coolFanService.updateCharacteristic(
        this.platform.api.hap.Characteristic.RotationSpeed,
        coolFanSpeed
      );
      
      // Store current cool mode speed
      this.coolModeFanSpeed = state.windSpeed;
    } else {
      this.coolFanService.updateCharacteristic(
        this.platform.api.hap.Characteristic.RotationSpeed,
        0
      );
    }
  }

  // AWS Error Recovery Helper Method
  async executeWithAWSRetry(operation, context = '') {
    try {
      return await operation();
    } catch (error) {
      // Check for AWS auth errors in any operation
      if (error.message.includes('Forbidden') || 
          error.message.includes('Credentials') || 
          error.message.includes('expired') ||
          error.message.includes('InvalidToken')) {
        this.log.warn(`🔄 AWS error in ${context}, re-authenticating...`);
        await this.platform.tclApi.handleAuthExpiry();
        
        // Retry once after re-auth
        try {
          return await operation();
        } catch (retryError) {
          this.log.error(`❌ ${context} failed even after re-auth:`, retryError.message);
          throw retryError;
        }
      }
      throw error; // Re-throw non-AWS errors
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
        ]  // Remove WRITE permission
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
        case 2: // Another cool mode variant
          return this.platform.api.hap.Characteristic.CurrentHeatingCoolingState.COOL;
        case 3:
          // Fan mode shows as running (COOL) not off
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
        case 2: // Another cool mode variant
          return this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL;
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
            windSpeed: this.coolModeFanSpeed, // Use saved cool mode speed
            ECO: 0,
            sleep: 0,
            turbo: 0,
            silenceSwitch: 0
          };
          this.log.info(`❄️ Setting AC to COOL mode with saved fan speed F${this.coolModeFanSpeed}`);
          setTimeout(() => this.enableTemperatureControl(), 500);
          break;
          
        case Characteristic.TargetHeatingCoolingState.AUTO:
          properties = {
            powerSwitch: 1,
            workMode: 3,
            windSpeed: this.fanModeFanSpeed  // Use saved fan mode speed
          };
          this.log.info(`💨 Setting AC to FAN mode with saved fan speed F${this.fanModeFanSpeed}`);
          setTimeout(() => this.disableTemperatureControl(), 500);
          break;
      }

      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setTargetHeatingCoolingState'
      );
      this.log.info(`🎯 Set heating/cooling state to ${value}`);
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

      // Update cache
      if (!this.platform.tclApi.currentDeviceState[this.device.deviceId]) {
        this.platform.tclApi.currentDeviceState[this.device.deviceId] = {};
      }
      this.platform.tclApi.currentDeviceState[this.device.deviceId].targetTemperature = temperature;

      // Force HomeKit update
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
      return state ? (state.powerSwitch === 1 && state.workMode === 3) : false;
    } catch (error) {
      this.log.error('❌ Error getting fan state:', error.message);
      return false;
    }
  }

  async setFanOn(value) {
    try {
      if (value) {
        // Turn on fan = switch to AUTO mode with saved fan speed
        this.log.info(`💨 FAN: Turning ON - switching to FAN mode`);
        const properties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: this.fanModeFanSpeed
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setFanOn'
        );
        
        // Update main thermostat to show AUTO
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
          );
          this.disableTemperatureControl();
        }, 500);
        
        this.log.info(`💨 FAN: ON with saved speed F${this.fanModeFanSpeed}`);
      } else {
        // Turn off fan = turn off everything
        const properties = {
          powerSwitch: 0
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setFanOff'
        );
        
        // Update main thermostat to show OFF
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF
          );
          this.enableTemperatureControl();
        }, 500);
        
        this.log.info(`💨 FAN: OFF`);
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
        return 0; // Fan is off if device is off
      }
      
      // Only show fan speed if actually in fan mode
      if (state.workMode !== 3) {
        return 0; // Fan is off if not in fan mode
      }
      
      // Fan mode mapping: F1=100% (High), F2=50% (Low)
      switch (state.windSpeed) {
        case 1: return 100;  // F1 = 100% (High speed)
        case 2: return 50;   // F2 = 50% (Low speed)
        default: return 50;
      }
    } catch (error) {
      this.log.error('❌ Error getting fan rotation speed:', error.message);
      return 50;
    }
  }

  async setRotationSpeed(value) {
    try {
      // Auto-switch to fan mode if not already
      const currentState = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      
      if (!currentState || currentState.workMode !== 3) {
        this.log.info(`💨 FAN SPEED: Auto-switching to fan mode`);
        const modeProperties = {
          powerSwitch: 1,
          workMode: 3,
          windSpeed: 2  // Default F2
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, modeProperties),
          'setRotationSpeed-autoSwitch'
        );
        
        // Update main thermostat
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.AUTO
          );
          this.disableTemperatureControl();
        }, 500);
        
        // Wait for mode switch
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // Fan mode mapping: 0-50% = F2 (Low), 51-100% = F1 (High)
      let fanSpeed;
      let fanName;
      
      if (value <= 50) {
        fanSpeed = 2;  // F2 hardware
        fanName = 'F2 (Low)';
      } else {
        fanSpeed = 1;  // F1 hardware  
        fanName = 'F1 (High)';
      }
      
      // Save the fan mode speed
      this.fanModeFanSpeed = fanSpeed;
      
      const properties = {
        windSpeed: fanSpeed
      };
      
      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setRotationSpeed'
      );
      this.log.info(`💨 FAN SPEED: Set to ${fanName} (${value}% → F${fanSpeed} for FAN mode)`);
    } catch (error) {
      this.log.error('❌ Error setting fan rotation speed:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }
  
  // Cool mode fan control methods
  async getCoolFanOn() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      return state ? (state.powerSwitch === 1 && (state.workMode === 0 || state.workMode === 2)) : false;
    } catch (error) {
      this.log.error('❌ Error getting cool fan state:', error.message);
      return false;
    }
  }

  async setCoolFanOn(value) {
    try {
      if (value) {
        // Turn on cool mode with saved fan speed
        this.log.info(`❄️ COOL FAN: Turning ON - switching to COOL mode`);
        const properties = {
          powerSwitch: 1,
          workMode: 0,
          windSpeed: this.coolModeFanSpeed,
          ECO: 0,
          sleep: 0,
          turbo: 0,
          silenceSwitch: 0
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setCoolFanOn'
        );
        
        // Update main thermostat to show COOL
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL
          );
          this.enableTemperatureControl();
        }, 500);
        
        this.log.info(`❄️ COOL FAN: ON with saved speed F${this.coolModeFanSpeed}`);
      } else {
        // Turn off cool fan = turn off everything
        const properties = {
          powerSwitch: 0
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
          'setCoolFanOff'
        );
        
        // Update main thermostat to show OFF
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.OFF
          );
          this.enableTemperatureControl();
        }, 500);
        
        this.log.info(`❄️ COOL FAN: OFF`);
      }
    } catch (error) {
      this.log.error('❌ Error setting cool fan state:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }

  async getCoolFanSpeed() {
    try {
      const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      if (!state || !state.powerSwitch || (state.workMode !== 0 && state.workMode !== 2)) {
        return 0; // Cool fan is off if device is off or not in cool mode
      }
      
      // Cool mode mapping: F1=100% (High), F2/Auto=50% (Low)
      switch (state.windSpeed) {
        case 1: return 100;  // F1 = 100% (High speed)
        case 2:
        case 0:
        default: return 50;   // F2/Auto = 50% (Low speed)
      }
    } catch (error) {
      this.log.error('❌ Error getting cool fan speed:', error.message);
      return 50;
    }
  }

  async setCoolFanSpeed(value) {
    try {
      // Auto-switch to cool mode if not already
      const currentState = await this.platform.tclApi.getDeviceState(this.device.deviceId);
      
      if (!currentState || (currentState.workMode !== 0 && currentState.workMode !== 2)) {
        this.log.info(`❄️ COOL FAN SPEED: Auto-switching to cool mode`);
        const modeProperties = {
          powerSwitch: 1,
          workMode: 0, // Use mode 0 (standard cool)
          windSpeed: this.coolModeFanSpeed,
          ECO: 0,
          sleep: 0,
          turbo: 0,
          silenceSwitch: 0
        };
        await this.executeWithAWSRetry(
          () => this.platform.tclApi.setDeviceState(this.device.deviceId, modeProperties),
          'setCoolFanSpeed-autoSwitch'
        );
        
        // Update main thermostat
        setTimeout(() => {
          this.service.updateCharacteristic(
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState,
            this.platform.api.hap.Characteristic.TargetHeatingCoolingState.COOL
          );
          this.enableTemperatureControl();
        }, 500);
        
        // Wait for mode switch
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // Cool mode mapping: 0-50% = F2 (Low), 51-100% = F1 (High)
      let fanSpeed;
      let fanName;
      
      if (value <= 50) {
        fanSpeed = 2;  // F2 hardware
        fanName = 'F2 (Low)';
      } else {
        fanSpeed = 1;  // F1 hardware  
        fanName = 'F1 (High)';
      }
      
      // Save the cool mode speed
      this.coolModeFanSpeed = fanSpeed;
      
      const properties = {
        windSpeed: fanSpeed
      };
      
      await this.executeWithAWSRetry(
        () => this.platform.tclApi.setDeviceState(this.device.deviceId, properties),
        'setCoolFanSpeed'
      );
      this.log.info(`❄️ COOL FAN SPEED: Set to ${fanName} (${value}% → F${fanSpeed} for COOL mode)`);
    } catch (error) {
      this.log.error('❌ Error setting cool fan speed:', error.message);
      throw new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
    }
  }
  
  startPolling() {
    // Reduced polling frequency since we have live updates
    setInterval(async () => {
      try {
        const state = await this.platform.tclApi.getDeviceState(this.device.deviceId);
        if (state) {
          // Skip update if we recently got a live update
          const timeSinceLastUpdate = Date.now() - this.lastDeviceUpdate;
          if (timeSinceLastUpdate < 5000) {
            this.platform.tclApi.debug('🗑️ Skipping polling update (recent live update)');
            return;
          }
          
          // Reset error tracking on successful poll
          this.consecutiveErrors = 0;
          this.lastSuccessfulPoll = Date.now();
          
          // Use the live update handler for consistency
          this.updateHomeKitFromState(state);
          
          this.platform.tclApi.debug(`🔄 Polling sync: Power=${state.powerSwitch}, Mode=${state.workMode}, WindSpeed=${state.windSpeed}`);
        }
      } catch (error) {
        this.platform.tclApi.debug('🔄 Polling update:', error.message);
        
        // AWS Error Recovery & Connection Health Monitoring
        this.consecutiveErrors++;
        
        // Check for AWS authentication issues
        if (error.message.includes('Forbidden') || 
            error.message.includes('Credentials') || 
            error.message.includes('expired') ||
            error.message.includes('InvalidToken')) {
          this.log.warn('🔄 AWS credentials issue detected, re-authenticating...');
          await this.platform.tclApi.handleAuthExpiry();
          this.consecutiveErrors = 0; // Reset on auth attempt
          return;
        }
        
        // Check for multiple consecutive failures
        if (this.consecutiveErrors >= 3) {
          this.log.warn(`🔄 ${this.consecutiveErrors} consecutive failures detected, triggering re-authentication`);
          await this.platform.tclApi.handleAuthExpiry();
          this.consecutiveErrors = 0; // Reset after auth attempt
        }
        
        // Log connection health status
        const timeSinceLastSuccess = Date.now() - this.lastSuccessfulPoll;
        if (timeSinceLastSuccess > 60000) { // 1 minute
          this.log.warn(`🔌 Connection degraded: ${Math.round(timeSinceLastSuccess/1000)}s since last successful poll`);
        }
      }
    }, 30000); // 30-second polling as backup (live updates handle real-time)
  }
}
