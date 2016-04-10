var _dec, _class2, _dec2, _class3, _dec3, _class4, _dec4, _class5, _dec5, _class6, _dec6, _class7, _dec7, _class9;

import extend from 'extend';
import { parseQueryString, join, buildQueryString } from 'aurelia-path';
import { inject } from 'aurelia-dependency-injection';
import { Redirect } from 'aurelia-router';
import { HttpClient } from 'aurelia-fetch-client';
import { Config, Rest } from 'aurelia-api';

export let Popup = class Popup {
  constructor() {
    this.popupWindow = null;
    this.polling = null;
    this.url = '';
  }

  open(url, windowName, options, redirectUri) {
    this.url = url;
    const optionsString = buildPopupWindowOptions(options || {});

    this.popupWindow = window.open(url, windowName, optionsString);

    if (this.popupWindow && this.popupWindow.focus) {
      this.popupWindow.focus();
    }

    return this;
  }

  eventListener(redirectUri) {
    return new Promise((resolve, reject) => {
      this.popupWindow.addEventListener('loadstart', event => {
        if (event.url.indexOf(redirectUri) !== 0) {
          return;
        }

        const parser = document.createElement('a');
        parser.href = event.url;

        if (parser.search || parser.hash) {
          const qs = parseUrl(parser);

          if (qs.error) {
            reject({ error: qs.error });
          } else {
            resolve(qs);
          }

          this.popupWindow.close();
        }
      });

      this.popupWindow.addEventListener('exit', () => {
        reject({ data: 'Provider Popup was closed' });
      });

      this.popupWindow.addEventListener('loaderror', () => {
        reject({ data: 'Authorization Failed' });
      });
    });
  }

  pollPopup() {
    return new Promise((resolve, reject) => {
      this.polling = setInterval(() => {
        let errorData;

        try {
          if (this.popupWindow.location.host === document.location.host && (this.popupWindow.location.search || this.popupWindow.location.hash)) {
            const qs = parseUrl(this.popupWindow.location);

            if (qs.error) {
              reject({ error: qs.error });
            } else {
              resolve(qs);
            }

            this.popupWindow.close();
            clearInterval(this.polling);
          }
        } catch (error) {
          errorData = error;
        }

        if (!this.popupWindow) {
          clearInterval(this.polling);
          reject({
            error: errorData,
            data: 'Provider Popup Blocked'
          });
        } else if (this.popupWindow.closed) {
          clearInterval(this.polling);
          reject({
            error: errorData,
            data: 'Problem poll popup'
          });
        }
      }, 35);
    });
  }
};

const buildPopupWindowOptions = options => {
  const width = options.width || 500;
  const height = options.height || 500;

  const extended = extend({
    width: width,
    height: height,
    left: window.screenX + (window.outerWidth - width) / 2,
    top: window.screenY + (window.outerHeight - height) / 2.5
  }, options);

  let parts = [];
  Object.keys(extended).map(key => parts.push(key + '=' + extended[key]));

  return parts.join(',');
};

const parseUrl = url => {
  return extend(true, {}, parseQueryString(url.search), parseQueryString(url.hash));
};

export let BaseConfig = class BaseConfig {
  constructor() {
    this.client = null;
    this.endpoint = null;
    this.configureEndpoints = null;
    this.loginRedirect = '#/customer';
    this.logoutRedirect = '#/';
    this.loginRoute = '/login';
    this.loginOnSignup = true;
    this.signupRedirect = '#/login';
    this.baseUrl = '';
    this.loginUrl = '/auth/login';
    this.signupUrl = '/auth/signup';
    this.profileUrl = '/auth/me';
    this.unlinkUrl = '/auth/unlink/';
    this.unlinkMethod = 'get';
    this.authHeader = 'Authorization';
    this.authTokenType = 'Bearer';
    this.accessTokenProp = 'access_token';
    this.accessTokenName = 'token';
    this.accessTokenRoot = false;
    this.useRefreshToken = false;
    this.autoUpdateToken = true;
    this.clientId = false;
    this.refreshTokenProp = 'refresh_token';
    this.refreshTokenName = 'token';
    this.refreshTokenRoot = false;
    this.httpInterceptor = true;
    this.withCredentials = true;
    this.platform = 'browser';
    this.storage = 'localStorage';
    this.accessTokenStorage = 'aurelia_access_token';
    this.refreshTokenStorage = 'aurelia_refresh_token';
    this.providers = {
      google: {
        name: 'google',
        url: '/auth/google',
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/auth',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        scope: ['profile', 'email'],
        scopePrefix: 'openid',
        scopeDelimiter: ' ',
        requiredUrlParams: ['scope'],
        optionalUrlParams: ['display'],
        display: 'popup',
        type: '2.0',
        popupOptions: {
          width: 452,
          height: 633
        }
      },
      facebook: {
        name: 'facebook',
        url: '/auth/facebook',
        authorizationEndpoint: 'https://www.facebook.com/v2.3/dialog/oauth',
        redirectUri: window.location.origin + '/' || window.location.protocol + '//' + window.location.host + '/',
        scope: ['email'],
        scopeDelimiter: ',',
        nonce: function () {
          return Math.random();
        },
        requiredUrlParams: ['nonce', 'display', 'scope'],
        display: 'popup',
        type: '2.0',
        popupOptions: {
          width: 580,
          height: 400
        }
      },
      linkedin: {
        name: 'linkedin',
        url: '/auth/linkedin',
        authorizationEndpoint: 'https://www.linkedin.com/uas/oauth2/authorization',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        requiredUrlParams: ['state'],
        scope: ['r_emailaddress'],
        scopeDelimiter: ' ',
        state: 'STATE',
        type: '2.0',
        popupOptions: {
          width: 527,
          height: 582
        }
      },
      github: {
        name: 'github',
        url: '/auth/github',
        authorizationEndpoint: 'https://github.com/login/oauth/authorize',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        optionalUrlParams: ['scope'],
        scope: ['user:email'],
        scopeDelimiter: ' ',
        type: '2.0',
        popupOptions: {
          width: 1020,
          height: 618
        }
      },
      yahoo: {
        name: 'yahoo',
        url: '/auth/yahoo',
        authorizationEndpoint: 'https://api.login.yahoo.com/oauth2/request_auth',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        scope: [],
        scopeDelimiter: ',',
        type: '2.0',
        popupOptions: {
          width: 559,
          height: 519
        }
      },
      twitter: {
        name: 'twitter',
        url: '/auth/twitter',
        authorizationEndpoint: 'https://api.twitter.com/oauth/authenticate',
        type: '1.0',
        popupOptions: {
          width: 495,
          height: 645
        }
      },
      live: {
        name: 'live',
        url: '/auth/live',
        authorizationEndpoint: 'https://login.live.com/oauth20_authorize.srf',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        scope: ['wl.emails'],
        scopeDelimiter: ' ',
        requiredUrlParams: ['display', 'scope'],
        display: 'popup',
        type: '2.0',
        popupOptions: {
          width: 500,
          height: 560
        }
      },
      instagram: {
        name: 'instagram',
        url: '/auth/instagram',
        authorizationEndpoint: 'https://api.instagram.com/oauth/authorize',
        redirectUri: window.location.origin || window.location.protocol + '//' + window.location.host,
        requiredUrlParams: ['scope'],
        scope: ['basic'],
        scopeDelimiter: '+',
        display: 'popup',
        type: '2.0',
        popupOptions: {
          width: 550,
          height: 369
        }
      }
    };
    this._authToken = 'Bearer';
    this._responseTokenProp = 'access_token';
    this._tokenName = 'token';
    this._tokenRoot = false;
    this._tokenPrefix = 'aurelia';
  }

  withBase(url) {
    return join(this.baseUrl, url);
  }

  configure(incomming) {
    for (let key in incomming) {
      const value = incomming[key];
      if (value !== undefined) {
        if (Array.isArray(value) || typeof value !== 'object' || value === null) {
          this[key] = value;
        } else {
          extend(true, this[key], value);
        }
      }
    }
  }

  get current() {
    console.warn('BaseConfig.current() is deprecated. Use BaseConfig directly instead.');
    return this;
  }

  set authToken(authToken) {
    console.warn('BaseConfig.authToken is deprecated. Use BaseConfig.authTokenType instead.');
    this._authTokenType = authToken;
    this.authTokenType = authToken;
    return authToken;
  }
  get authToken() {
    return this._authTokenType;
  }

  set responseTokenProp(responseTokenProp) {
    console.warn('BaseConfig.responseTokenProp is deprecated. Use BaseConfig.accessTokenProp instead.');
    this._responseTokenProp = responseTokenProp;
    this.accessTokenProp = responseTokenProp;
    return responseTokenProp;
  }
  get responseTokenProp() {
    return this._responseTokenProp;
  }

  set tokenRoot(tokenRoot) {
    console.warn('BaseConfig.tokenRoot is deprecated. Use BaseConfig.accessTokenRoot instead.');
    this._tokenRoot = tokenRoot;
    this.accessTokenRoot = tokenRoot;
    return tokenRoot;
  }
  get tokenRoot() {
    return this._tokenRoot;
  }

  set tokenName(tokenName) {
    console.warn('BaseConfig.tokenName is deprecated. Use BaseConfig.accessTokenName instead.');
    this._tokenName = tokenName;
    this.accessTokenName = tokenName;
    this.accessTokenStorage = this.tokenPrefix ? this.tokenPrefix + '_' + this.tokenName : this.tokenName;
    return tokenName;
  }
  get tokenName() {
    return this._tokenName;
  }

  set tokenPrefix(tokenPrefix) {
    console.warn('BaseConfig.tokenPrefix is deprecated. Use BaseConfig.accessTokenStorage instead.');
    this._tokenPrefix = tokenPrefix;
    this.accessTokenStorage = this.tokenPrefix ? this.tokenPrefix + '_' + this.tokenName : this.tokenName;
    return tokenPrefix;
  }
  get tokenPrefix() {
    return this._tokenPrefixx;
  }
};

export let Storage = (_dec = inject(BaseConfig), _dec(_class2 = class Storage {
  constructor(config) {
    this.config = config;
  }

  get(key) {
    if (window[this.config.storage]) {
      return window[this.config.storage].getItem(key);
    }
  }

  set(key, value) {
    if (window[this.config.storage]) {
      return window[this.config.storage].setItem(key, value);
    }
  }

  remove(key) {
    if (window[this.config.storage]) {
      return window[this.config.storage].removeItem(key);
    }
  }
}) || _class2);

export let OAuth1 = (_dec2 = inject(Storage, Popup, BaseConfig), _dec2(_class3 = class OAuth1 {
  constructor(storage, popup, config) {
    this.storage = storage;
    this.config = config;
    this.popup = popup;
    this.defaults = {
      url: null,
      name: null,
      popupOptions: null,
      redirectUri: null,
      authorizationEndpoint: null
    };
  }

  open(options, userData) {
    const provider = extend(true, {}, this.defaults, options);
    const serverUrl = this.config.withBase(provider.url);

    if (this.config.platform !== 'mobile') {
      this.popup = this.popup.open('', provider.name, provider.popupOptions, provider.redirectUri);
    }

    return this.config.client.post(serverUrl).then(response => {
      const url = provider.authorizationEndpoint + '?' + buildQueryString(response);

      if (this.config.platform === 'mobile') {
        this.popup = this.popup.open(url, provider.name, provider.popupOptions, provider.redirectUri);
      } else {
        this.popup.popupWindow.location = url;
      }

      const popupListener = this.config.platform === 'mobile' ? this.popup.eventListener(provider.redirectUri) : this.popup.pollPopup();

      return popupListener.then(result => this.exchangeForToken(result, userData, provider));
    });
  }

  exchangeForToken(oauthData, userData, provider) {
    const data = extend(true, {}, userData, oauthData);
    const serverUrl = this.config.withBase(provider.url);
    const credentials = this.config.withCredentials ? 'include' : 'same-origin';

    return this.config.client.post(serverUrl, data, { credentials: credentials });
  }
}) || _class3);

export let OAuth2 = (_dec3 = inject(Storage, Popup, BaseConfig), _dec3(_class4 = class OAuth2 {
  constructor(storage, popup, config) {
    this.storage = storage;
    this.config = config;
    this.popup = popup;
    this.defaults = {
      url: null,
      name: null,
      state: null,
      scope: null,
      scopeDelimiter: null,
      redirectUri: null,
      popupOptions: null,
      authorizationEndpoint: null,
      responseParams: null,
      requiredUrlParams: null,
      optionalUrlParams: null,
      defaultUrlParams: ['response_type', 'client_id', 'redirect_uri'],
      responseType: 'code'
    };
  }

  open(options, userData) {
    const provider = extend(true, {}, this.defaults, options);
    const stateName = provider.name + '_state';

    if (typeof provider.state === 'function') {
      this.storage.set(stateName, provider.state());
    } else if (typeof provider.state === 'string') {
      this.storage.set(stateName, provider.state);
    }

    const url = provider.authorizationEndpoint + '?' + buildQueryString(this.buildQuery(provider));
    const popup = this.popup.open(url, provider.name, provider.popupOptions, provider.redirectUri);
    const openPopup = this.config.platform === 'mobile' ? popup.eventListener(provider.redirectUri) : popup.pollPopup();

    return openPopup.then(oauthData => {
      if (provider.responseType === 'token' || provider.responseType === 'id_token%20token' || provider.responseType === 'token%20id_token') {
        return oauthData;
      }
      if (oauthData.state && oauthData.state !== this.storage.get(stateName)) {
        return Promise.reject('OAuth 2.0 state parameter mismatch.');
      }
      return this.exchangeForToken(oauthData, userData, provider);
    });
  }

  exchangeForToken(oauthData, userData, provider) {
    const data = extend(true, {}, userData, {
      clientId: provider.clientId,
      redirectUri: provider.redirectUri
    }, oauthData);

    const serverUrl = this.config.withBase(provider.url);
    const credentials = this.config.withCredentials ? 'include' : 'same-origin';

    return this.config.client.post(serverUrl, data, { credentials: credentials });
  }

  buildQuery(provider) {
    let query = {};
    const urlParams = ['defaultUrlParams', 'requiredUrlParams', 'optionalUrlParams'];

    urlParams.forEach(params => {
      (provider[params] || []).forEach(paramName => {
        const camelizedName = camelCase(paramName);
        let paramValue = typeof provider[paramName] === 'function' ? provider[paramName]() : provider[camelizedName];

        if (paramName === 'state') {
          paramValue = encodeURIComponent(this.storage.get(provider.name + '_state'));
        }

        if (paramName === 'scope' && Array.isArray(paramValue)) {
          paramValue = paramValue.join(provider.scopeDelimiter);

          if (provider.scopePrefix) {
            paramValue = provider.scopePrefix + provider.scopeDelimiter + paramValue;
          }
        }

        query[paramName] = paramValue;
      });
    });
    return query;
  }
}) || _class4);

const camelCase = function (name) {
  return name.replace(/([\:\-\_]+(.))/g, function (_, separator, letter, offset) {
    return offset ? letter.toUpperCase() : letter;
  });
};

export let Authentication = (_dec4 = inject(Storage, BaseConfig, OAuth1, OAuth2), _dec4(_class5 = class Authentication {
  constructor(storage, config, oAuth1, oAuth2) {
    this.storage = storage;
    this.config = config;
    this.oAuth1 = oAuth1;
    this.oAuth2 = oAuth2;
  }

  getLoginRoute() {
    console.warn('Authentication.getLoginRoute is deprecated. Use baseConfig.loginRoute instead.');
    return this.config.loginRoute;
  }

  getLoginRedirect() {
    console.warn('Authentication.getLoginRedirect is deprecated. Use baseConfig.loginRedirect instead.');
    return this.config.loginRedirect;
  }

  getLoginUrl() {
    console.warn('Authentication.getLoginUrl is deprecated. Use baseConfig.withBase(baseConfig.loginUrl) instead.');
    return this.config.withBase(this.config.loginUrl);
  }

  getSignupUrl() {
    console.warn('Authentication.getSignupUrl is deprecated. Use baseConfig.withBase(baseConfig.signupUrl) instead.');
    return this.config.withBase(this.config.signupUrl);
  }

  getProfileUrl() {
    console.warn('Authentication.getProfileUrl is deprecated. Use baseConfig.withBase(baseConfig.profileUrl) instead.');
    return this.config.withBase(this.config.profileUrl);
  }

  getToken() {
    console.warn('Authentication.getToken is deprecated. Use .accessToken instead.');
    return this.accessToken;
  }

  getRefreshToken() {
    console.warn('Authentication.getRefreshToken is deprecated. Use .refreshToken instead.');
    return this.refreshToken;
  }


  get accessToken() {
    return this.storage.get(this.config.accessTokenStorage);
  }

  set accessToken(newToken) {
    if (newToken) {
      return this.storage.set(this.config.accessTokenStorage, newToken);
    }
    return this.storage.remove(this.config.accessTokenStorage);
  }

  get refreshToken() {
    return this.storage.get(this.config.refreshTokenStorage);
  }

  set refreshToken(newToken) {
    if (newToken) {
      return this.storage.set(this.config.refreshTokenStorage, newToken);
    }
    return this.storage.remove(this.config.refreshTokenStorage);
  }

  getPayload() {
    const accessToken = this.accessToken;
    if (accessToken && accessToken.split('.').length === 3) {
      try {
        const base64Url = this.accessToken.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(decodeURIComponent(escape(window.atob(base64))));
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  isTokenExpired() {
    const payload = this.getPayload();
    const exp = payload && payload.exp;
    if (exp) {
      return Math.round(new Date().getTime() / 1000) > exp;
    }
    return undefined;
  }

  isAuthenticated() {
    if (!this.accessToken) {
      return false;
    }

    if (this.accessToken.split('.').length !== 3) {
      return true;
    }

    return this.isTokenExpired() !== true;
  }

  getTokenFromResponse(response, tokenProp, tokenName, tokenRoot) {
    if (!response) return null;

    const responseTokenProp = response[tokenProp];

    if (typeof responseTokenProp === 'string') {
      return responseTokenProp;
    }

    if (typeof responseTokenProp === 'object') {
      const tokenRootData = tokenRoot && tokenRoot.split('.').reduce(function (o, x) {
        return o[x];
      }, responseTokenProp);
      return tokenRootData ? tokenRootData[tokenName] : responseTokenProp[tokenName];
    }

    return response[tokenName] === undefined ? null : response[tokenName];
  }

  setAccessTokenFromResponse(response) {
    const config = this.config;
    const newToken = this.getTokenFromResponse(response, config.accessTokenProp, config.accessTokenName, config.accessTokenRoot);

    if (!newToken) throw new Error('Token not found in response');

    this.accessToken = newToken;
  }

  setRefreshTokenFromResponse(response) {
    const config = this.config;
    const newToken = this.getTokenFromResponse(response, config.refreshTokenProp, config.refreshTokenName, config.refreshTokenRoot);

    if (!newToken) throw new Error('Token not found in response');

    this.refreshToken = newToken;
  }

  setTokensFromResponse(response) {
    this.setAccessTokenFromResponse(response);

    if (this.config.useRefreshToken) {
      this.setRefreshTokenFromResponse(response);
    }
  }

  removeTokens() {
    this.accessToken = null;
    this.refreshToken = null;
  }

  logout() {
    return new Promise(resolve => {
      this.removeTokens();

      resolve();
    });
  }

  authenticate(name, userData = {}) {
    const provider = this.config.providers[name].type === '1.0' ? this.oAuth1 : this.oAuth2;

    return provider.open(this.config.providers[name], userData);
  }

  redirect(redirectUrl, defaultRedirectUrl) {
    if (redirectUrl === true) {
      console.warn('Setting redirectUrl === true to actually not redirect is deprecated. Set redirectUrl===false instead.');
      return;
    }

    if (redirectUrl === false) {
      console.warn('Setting redirectUrl === false to actually use the defaultRedirectUrl has changed. It means "Do not redirect" now. Set redirectUrl to undefined or null to use the defaultRedirectUrl.');
      return;
    }
    if (typeof redirectUrl === 'string') {
      window.location.href = window.encodeURI(redirectUrl);
    } else if (defaultRedirectUrl) {
      window.location.href = defaultRedirectUrl;
    }
  }
}) || _class5);

export let AuthorizeStep = (_dec5 = inject(Authentication), _dec5(_class6 = class AuthorizeStep {
  constructor(authentication) {
    this.authentication = authentication;
  }

  run(routingContext, next) {
    const isLoggedIn = this.authentication.isAuthenticated();
    const loginRoute = this.authentication.config.loginRoute;

    if (routingContext.getAllInstructions().some(i => i.config.auth)) {
      if (!isLoggedIn) {
        return next.cancel(new Redirect(loginRoute));
      }
    } else if (isLoggedIn && routingContext.getAllInstructions().some(i => i.fragment === loginRoute)) {
      return next.cancel(new Redirect(this.authentication.config.loginRedirect));
    }

    return next();
  }
}) || _class6);

export let AuthService = (_dec6 = inject(Authentication, BaseConfig), _dec6(_class7 = class AuthService {
  constructor(authentication, config) {
    this.isRefreshing = false;

    this.authentication = authentication;
    this.config = config;
  }

  get client() {
    return this.config.client;
  }

  get auth() {
    console.warn('AuthService.auth is deprecated. Use .authentication instead.');
    return this.authentication;
  }

  getMe(criteria) {
    if (typeof criteria === 'string' || typeof criteria === 'number') {
      criteria = { id: criteria };
    }
    return this.client.find(this.config.withBase(this.config.profileUrl), criteria);
  }

  updateMe(body, criteria) {
    if (typeof criteria === 'string' || typeof criteria === 'number') {
      criteria = { id: criteria };
    }
    return this.client.update(this.config.withBase(this.config.profileUrl), criteria, body);
  }

  getAccessToken() {
    return this.authentication.accessToken;
  }

  getCurrentToken() {
    console.warn('AuthService.getCurrentToken() is deprecated. Use .getAccessToken() instead.');
    return this.getAccessToken();
  }

  getRefreshToken() {
    return this.authentication.refreshToken;
  }

  isAuthenticated() {
    const isExpired = this.authentication.isTokenExpired();
    if (isExpired && this.config.autoUpdateToken) {
      if (this.isRefreshing) {
        return true;
      }
      this.updateToken();
    }
    return this.authentication.isAuthenticated();
  }

  isTokenExpired() {
    return this.authentication.isTokenExpired();
  }

  getTokenPayload() {
    return this.authentication.getPayload();
  }

  signup(displayName, email, password) {
    let content;

    if (typeof arguments[0] === 'object') {
      content = arguments[0];
    } else {
      console.warn('AuthService.signup(displayName, email, password) is deprecated. Provide an object with signup data instead.');
      content = {
        'displayName': displayName,
        'email': email,
        'password': password
      };
    }
    return this._signup(content);
  }

  _signup(data, redirectUri) {
    return this.client.post(this.config.withBase(this.config.signupUrl), data).then(response => {
      if (this.config.loginOnSignup) {
        this.authentication.setTokensFromResponse(response);
      }
      this.authentication.redirect(redirectUri, this.config.signupRedirect);

      return response;
    });
  }

  login(email, password) {
    let content = {};

    if (typeof arguments[1] !== 'string') {
      content = arguments[0];
    } else {
      console.warn('AuthService.login(email, password) is deprecated. Provide an object with login data instead.');
      content = { email: email, password: password };
    }

    return this._login(content);
  }

  _login(data, redirectUri) {
    if (this.config.clientId) {
      data.client_id = this.config.clientId;
    }

    return this.client.post(this.config.withBase(this.config.loginUrl), data).then(response => {
      this.authentication.setTokensFromResponse(response);

      this.authentication.redirect(redirectUri, this.config.loginRedirect);

      return response;
    });
  }

  logout(redirectUri) {
    return this.authentication.logout(redirectUri).then(response => {
      this.authentication.redirect(redirectUri, this.config.logoutRedirect);

      return response;
    });
  }

  updateToken() {
    this.isRefreshing = true;
    const refreshToken = this.authentication.refreshToken;
    let content = {};

    if (refreshToken) {
      content = { grant_type: 'refresh_token', refresh_token: refreshToken };
      if (this.config.clientId) {
        content.client_id = this.config.clientId;
      }

      return this.client.post(this.config.withBase(this.config.loginUrl), content).then(response => {
        this.authentication.setTokensFromResponse(response);
        return response;
      }).catch(err => {
        this.authentication.removeTokens();
        throw err;
      }).then(response => {
        this.isRefreshing = false;
        return response;
      });
    }

    return Promise.reject('refreshToken not enabled');
  }

  authenticate(name, redirectUri, userData = {}) {
    return this.authentication.authenticate(name, userData).then(response => {
      this.authentication.setTokensFromResponse(response);

      this.authentication.redirect(redirectUri, this.config.loginRedirect);

      return response;
    });
  }

  unlink(name, redirectUri) {
    const unlinkUrl = this.config.withBase(this.config.unlinkUrl) + name;
    return this.client.request(this.config.unlinkMethod, unlinkUrl).then(response => {
      this.authentication.redirect(redirectUri);

      return response;
    });
  }
}) || _class7);

export let FetchConfig = (_dec7 = inject(HttpClient, Config, AuthService, BaseConfig), _dec7(_class9 = class FetchConfig {
  constructor(httpClient, clientConfig, authService, config) {
    this.httpClient = httpClient;
    this.clientConfig = clientConfig;
    this.authService = authService;
    this.config = config;
  }

  get interceptor() {
    return {
      request: request => {
        if (!this.config.httpInterceptor || !this.authService.isAuthenticated()) {
          return request;
        }
        let token = this.authService.getAccessToken();

        if (this.config.authTokenType) {
          token = `${ this.config.authTokenType } ${ token }`;
        }

        request.headers.set(this.config.authHeader, token);

        return request;
      },
      response: (response, request) => {
        return new Promise((resolve, reject) => {
          if (response.ok) {
            return resolve(response);
          }
          if (response.status !== 401) {
            return resolve(response);
          }
          if (!this.config.httpInterceptor || !this.authService.isTokenExpired()) {
            return resolve(response);
          }
          if (!this.config.useRefreshToken || !this.authService.getRefreshToken()) {
            return resolve(response);
          }

          this.authService.updateToken().then(() => {
            let token = this.authService.getAccessToken();

            if (this.config.authTokenType) {
              token = `${ this.config.authTokenType } ${ token }`;
            }

            request.headers.set(this.config.authHeader, token);

            return this.client.fetch(request).then(resolve);
          });
        });
      }
    };
  }

  configure(client) {
    if (Array.isArray(client)) {
      let configuredClients = [];
      client.forEach(toConfigure => {
        configuredClients.push(this.configure(toConfigure));
      });

      return configuredClients;
    }

    if (typeof client === 'string') {
      const endpoint = this.clientConfig.getEndpoint(client);
      if (!endpoint) {
        throw new Error(`There is no '${ client || 'default' }' endpoint registered.`);
      }
      client = endpoint.client;
    } else if (client instanceof Rest) {
      client = client.client;
    } else if (!(client instanceof HttpClient)) {
      client = this.httpClient;
    }

    client.interceptors.push(this.interceptor);

    return client;
  }
}) || _class9);

import './authFilter';

function configure(aurelia, config) {
  aurelia.globalResources('./authFilter');

  const baseConfig = aurelia.container.get(BaseConfig);

  if (typeof config === 'function') {
    config(baseConfig);
  } else if (typeof config === 'object') {
    baseConfig.configure(config);
  }

  const fetchConfig = aurelia.container.get(FetchConfig);
  const clientConfig = aurelia.container.get(Config);

  if (Array.isArray(baseConfig.configureEndpoints)) {
    baseConfig.configureEndpoints.forEach(endpointToPatch => {
      fetchConfig.configure(endpointToPatch);
    });
  }

  let client;

  if (baseConfig.endpoint !== null) {
    if (typeof baseConfig.endpoint === 'string') {
      const endpoint = clientConfig.getEndpoint(baseConfig.endpoint);
      if (!endpoint) {
        throw new Error(`There is no '${ baseConfig.endpoint || 'default' }' endpoint registered.`);
      }
      client = endpoint;
    } else if (baseConfig.endpoint instanceof HttpClient) {
      client = new Rest(baseConfig.endpoint);
    }
  }

  if (!(client instanceof Rest)) {
    client = new Rest(aurelia.container.get(HttpClient));
  }

  baseConfig.client = client;
}

export { configure, FetchConfig, AuthService, AuthorizeStep };