import extend from 'extend';
import {parseQueryString,join,buildQueryString} from 'aurelia-path';
import {inject} from 'aurelia-dependency-injection';
import {Redirect} from 'aurelia-router';
import {HttpClient} from 'aurelia-fetch-client';
import {Config,Rest} from 'aurelia-api';

export class Popup {
  constructor() {
    this.popupWindow = null;
    this.polling     = null;
    this.url         = '';
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

        const parser  = document.createElement('a');
        parser.href = event.url;

        if (parser.search || parser.hash) {
          const qs = parseUrl(parser);

          if (qs.error) {
            reject({error: qs.error});
          } else {
            resolve(qs);
          }

          this.popupWindow.close();
        }
      });

      this.popupWindow.addEventListener('exit', () => {
        reject({data: 'Provider Popup was closed'});
      });

      this.popupWindow.addEventListener('loaderror', () => {
        reject({data: 'Authorization Failed'});
      });
    });
  }

  pollPopup() {
    return new Promise((resolve, reject) => {
      this.polling = setInterval(() => {
        let errorData;

        try {
          if (this.popupWindow.location.host ===  document.location.host
            && (this.popupWindow.location.search || this.popupWindow.location.hash)) {
            const qs = parseUrl(this.popupWindow.location);

            if (qs.error) {
              reject({error: qs.error});
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
}

const buildPopupWindowOptions = options => {
  const width  = options.width || 500;
  const height = options.height || 500;

  const extended = extend({
    width: width,
    height: height,
    left: window.screenX + ((window.outerWidth - width) / 2),
    top: window.screenY + ((window.outerHeight - height) / 2.5)
  }, options);

  let parts = [];
  Object.keys(extended).map(key => parts.push(key + '=' + extended[key]));

  return parts.join(',');
};

const parseUrl = url => {
  return extend(true, {}, parseQueryString(url.search), parseQueryString(url.hash));
};

export class BaseConfig {
  // prepends baseUrl
  withBase(url) {
    return join(this.baseUrl, url);
  }

  // merge current settings with incomming settings
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

  /* ----------- default  config ----------- */

  // Used internally. The used Rest instance; set during configuration (see index.js)
  client = null;

  // If using aurelia-api:
  // =====================

  // This is the name of the endpoint used for any requests made in relation to authentication (login, logout, etc.). An empty string selects the default endpoint of aurelia-api.
  endpoint = null;
  // When authenticated, these endpoints will have the token added to the header of any requests (for authorization). Accepts an array of endpoint names. An empty string selects the default endpoint of aurelia-api.
  configureEndpoints = null;


  // SPA related options
  // ===================

  // The SPA url to which the user is redirected after a successful login
  loginRedirect = '#/customer';
  // The SPA url to which the user is redirected after a successful logout
  logoutRedirect = '#/';
  // The SPA route used when an unauthenticated user tries to access an SPA page that requires authentication
  loginRoute = '/login';
  // Whether or not an authentication token is provided in the response to a successful signup
  loginOnSignup = true;
  // If loginOnSignup == false: The SPA url to which the user is redirected after a successful signup (else loginRedirect is used)
  signupRedirect = '#/login';


  // API related options
  // ===================

  // The base url used for all authentication related requests, including provider.url below.
  // This appends to the httpClient/endpoint base url, it does not override it.
  baseUrl = '';
  // The API endpoint to which login requests are sent
  loginUrl = '/auth/login';
  // The API endpoint to which signup requests are sent
  signupUrl = '/auth/signup';
  // The API endpoint used in profile requests (inc. `find/get` and `update`)
  profileUrl = '/auth/me';
  // The API endpoint used with oAuth to unlink authentication
  unlinkUrl = '/auth/unlink/';
  // The HTTP method used for 'unlink' requests (Options: 'get' or 'post')
  unlinkMethod = 'get';


  // Token Options
  // =============

  // The header property used to contain the authToken in the header of API requests that require authentication
  authHeader = 'Authorization';
  // The token name used in the header of API requests that require authentication
  authTokenType = 'Bearer';
  // The the property from which to get the access token after a successful login or signup
  accessTokenProp = 'access_token';


  // If the property defined by `accessTokenProp` is an object:
  // ------------------------------------------------------------

  //This is the property from which to get the token `{ "accessTokenProp": { "accessTokenName" : '...' } }`
  accessTokenName = 'token';
  // This allows the token to be a further object deeper `{ "accessTokenProp": { "accessTokenRoot" : { "accessTokenName" : '...' } } }`
  accessTokenRoot = false;


  // Refresh Token Options
  // =====================

  // Option to turn refresh tokens On/Off
  useRefreshToken = false;
  // The option to enable/disable the automatic refresh of Auth tokens using Refresh Tokens
  autoUpdateToken = true;
  // Oauth Client Id
  clientId = false;
  // The the property from which to get the refresh token after a successful token refresh
  refreshTokenProp = 'refresh_token';

  // If the property defined by `refreshTokenProp` is an object:
  // -----------------------------------------------------------

  // This is the property from which to get the token `{ "refreshTokenProp": { "refreshTokenName" : '...' } }`
  refreshTokenName = 'token';
  // This allows the refresh token to be a further object deeper `{ "refreshTokenProp": { "refreshTokenRoot" : { "refreshTokenName" : '...' } } }`
  refreshTokenRoot = false;


  // Miscellaneous Options
  // =====================

  // Whether to enable the fetch interceptor which automatically adds the authentication headers
  // (or not... e.g. if using a session based API or you want to override the default behaviour)
  httpInterceptor = true;
  // For OAuth only: Tell the API whether or not to include token cookies in the response (for session based APIs)
  withCredentials = true;
  // Controls how the popup is shown for different devices (Options: 'browser' or 'mobile')
  platform = 'browser';
  // Determines the `window` property name upon which aurelia-authentication data is stored (Default: `window.localStorage`)
  storage = 'localStorage';
  // The property name used when storing the access token locally
  accessTokenStorage = 'aurelia_access_token';
  // The property name used when storing the refresh token locally
  refreshTokenStorage = 'aurelia_refresh_token';


  //OAuth provider specific related configuration
  // ============================================
  providers = {
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
      nonce: function() {
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

  /* deprecated defaults */
  _authToken = 'Bearer';
  _responseTokenProp = 'access_token';
  _tokenName = 'token';
  _tokenRoot = false;
  _tokenPrefix = 'aurelia';

  /* deprecated methods and parameteres */
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
}

@inject(BaseConfig)
export class Storage {
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
}

@inject(Storage, Popup, BaseConfig)
export class OAuth1 {
  constructor(storage, popup, config) {
    this.storage  = storage;
    this.config   = config;
    this.popup    = popup;
    this.defaults = {
      url: null,
      name: null,
      popupOptions: null,
      redirectUri: null,
      authorizationEndpoint: null
    };
  }

  open(options, userData) {
    const provider  = extend(true, {}, this.defaults, options);
    const serverUrl = this.config.withBase(provider.url);

    if (this.config.platform !== 'mobile') {
      this.popup = this.popup.open('', provider.name, provider.popupOptions, provider.redirectUri);
    }

    return this.config.client.post(serverUrl)
      .then(response => {
        const url = provider.authorizationEndpoint + '?' + buildQueryString(response);

        if (this.config.platform === 'mobile') {
          this.popup = this.popup.open(url, provider.name, provider.popupOptions,  provider.redirectUri);
        } else {
          this.popup.popupWindow.location = url;
        }

        const popupListener = this.config.platform === 'mobile'
                            ? this.popup.eventListener(provider.redirectUri)
                            : this.popup.pollPopup();

        return popupListener.then(result => this.exchangeForToken(result, userData, provider));
      });
  }

  exchangeForToken(oauthData, userData, provider) {
    const data        = extend(true, {}, userData, oauthData);
    const serverUrl   = this.config.withBase(provider.url);
    const credentials = this.config.withCredentials ? 'include' : 'same-origin';

    return this.config.client.post(serverUrl, data, {credentials: credentials});
  }
}

@inject(Storage, Popup, BaseConfig)
export class OAuth2 {
  constructor(storage, popup, config) {
    this.storage      = storage;
    this.config       = config;
    this.popup        = popup;
    this.defaults     = {
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
    const provider  = extend(true, {}, this.defaults, options);
    const stateName = provider.name + '_state';

    if (typeof provider.state === 'function') {
      this.storage.set(stateName, provider.state());
    } else if (typeof provider.state === 'string') {
      this.storage.set(stateName, provider.state);
    }

    const url       = provider.authorizationEndpoint
                    + '?' + buildQueryString(this.buildQuery(provider));
    const popup     = this.popup.open(url, provider.name, provider.popupOptions, provider.redirectUri);
    const openPopup = (this.config.platform === 'mobile')
                    ? popup.eventListener(provider.redirectUri)
                    : popup.pollPopup();

    return openPopup
      .then(oauthData => {
        if (provider.responseType === 'token' ||
            provider.responseType === 'id_token%20token' ||
            provider.responseType === 'token%20id_token'
        ) {
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

    const serverUrl   = this.config.withBase(provider.url);
    const credentials = this.config.withCredentials ? 'include' : 'same-origin';

    return this.config.client.post(serverUrl, data, {credentials: credentials});
  }

  buildQuery(provider) {
    let query = {};
    const urlParams   = ['defaultUrlParams', 'requiredUrlParams', 'optionalUrlParams'];

    urlParams.forEach( params => {
      (provider[params] || []).forEach( paramName => {
        const camelizedName = camelCase(paramName);
        let paramValue      = (typeof provider[paramName] === 'function')
                              ? provider[paramName]()
                              : provider[camelizedName];

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
}

const camelCase = function(name) {
  return name.replace(/([\:\-\_]+(.))/g, function(_, separator, letter, offset) {
    return offset ? letter.toUpperCase() : letter;
  });
};

@inject(Storage, BaseConfig, OAuth1, OAuth2)
export class Authentication {
  constructor(storage, config, oAuth1, oAuth2) {
    this.storage = storage;
    this.config  = config;
    this.oAuth1  = oAuth1;
    this.oAuth2  = oAuth2;
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
  /* getters/setters for tokens */

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


  /* work with the token */

  getPayload() {
    const accessToken = this.accessToken;
    if (accessToken && accessToken.split('.').length === 3) {
      try {
        const base64Url = this.accessToken.split('.')[1];
        const base64    = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(decodeURIComponent(escape(window.atob(base64))));
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  isTokenExpired() {
    const payload = this.getPayload();
    const exp     = payload && payload.exp;
    if (exp) {
      return Math.round(new Date().getTime() / 1000) > exp;
    }
    return undefined;
  }

  isAuthenticated() {
    // FAIL: There's no token, so user is not authenticated.
    if (!this.accessToken) {
      return false;
    }
    // PASS: There is a token, but in a different format
    if (this.accessToken.split('.').length !== 3) {
      return true;
    }
    // PASS: Non-JWT token that looks like JWT (isTokenExpired === undefined)
    // PASS or FAIL: test isTokenExpired.
    return this.isTokenExpired() !== true;
  }


  /* get and set token from response */

  getTokenFromResponse(response, tokenProp, tokenName, tokenRoot) {
    if (!response) return null;

    const responseTokenProp = response[tokenProp];

    if (typeof responseTokenProp === 'string') {
      return responseTokenProp;
    }

    if (typeof responseTokenProp === 'object') {
      const tokenRootData = tokenRoot && tokenRoot.split('.').reduce(function(o, x) { return o[x]; }, responseTokenProp);
      return tokenRootData ? tokenRootData[tokenName] : responseTokenProp[tokenName];
    }

    return response[tokenName] === undefined ? null : response[tokenName];
  }

  setAccessTokenFromResponse(response) {
    const config   = this.config;
    const newToken = this.getTokenFromResponse(response, config.accessTokenProp, config.accessTokenName, config.accessTokenRoot);

    if (!newToken) throw new Error('Token not found in response');

    this.accessToken = newToken;
  }

  setRefreshTokenFromResponse(response) {
    const config   = this.config;
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
    this.accessToken  = null;
    this.refreshToken = null;
  }

  logout() {
    return new Promise(resolve => {
      this.removeTokens();

      resolve();
    });
  }

  /**
   * Authenticate with third-party
   *
   * @param {String}    name of the provider
   * @param {[{}]}      [userData]
   *
   * @return {Promise<response>}
   *
   */
  authenticate(name, userData = {}) {
    const provider = this.config.providers[name].type === '1.0' ? this.oAuth1 : this.oAuth2;

    return provider.open(this.config.providers[name], userData);
  }

  redirect(redirectUrl, defaultRedirectUrl) {
    // stupid rule to keep it BC
    if (redirectUrl === true) {
      console.warn('Setting redirectUrl === true to actually not redirect is deprecated. Set redirectUrl===false instead.');
      return;
    }
    // explicit false means don't redirect
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
}

@inject(Authentication)
export class AuthorizeStep {
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
      return next.cancel(new Redirect( this.authentication.config.loginRedirect ));
    }

    return next();
  }
}

@inject(Authentication, BaseConfig)
export class AuthService {
  constructor(authentication, config) {
    this.authentication = authentication;
    this.config         = config;
  }

  /**
   * Set true during updateToken process
   *
   * @param {Boolean} isRefreshing
   */
   isRefreshing = false;

  /**
   * Getter: The configured client for all aurelia-authentication requests
   *
   * @return {HttpClient}
   *
   */
  get client() {
    return this.config.client;
  }

  get auth() {
    console.warn('AuthService.auth is deprecated. Use .authentication instead.');
    return this.authentication;
  }

  /**
   * Get current user profile from server
   *
   * @param {[{},Number,String]}  [criteria object or a Number|String converted to {id:criteria}]
   *
   * @return {Promise<response>}
   *
   */
  getMe(criteria) {
    if (typeof criteria === 'string' || typeof criteria === 'number') {
      criteria = {id: criteria};
    }
    return this.client.find(this.config.withBase(this.config.profileUrl), criteria);
  }

  /**
   * Send current user profile update to server
   *
   * @param {any}                 request body with data.
   * @param {[{},Number,String]}  [criteria object or a Number|String converted to {id:criteria}]
   *
   * @return {Promise<response>}
   *
   */
  updateMe(body, criteria) {
    if (typeof criteria === 'string' || typeof criteria === 'number') {
      criteria = { id: criteria };
    }
    return this.client.update(this.config.withBase(this.config.profileUrl), criteria, body);
  }

  /**
   * Get accessToken from storage
   *
   * @returns {String} current accessToken
   *
   */
  getAccessToken() {
    return this.authentication.accessToken;
  }

  getCurrentToken() {
    console.warn('AuthService.getCurrentToken() is deprecated. Use .getAccessToken() instead.');
    return this.getAccessToken();
  }

  /**
   * Get refreshToken from storage
   *
   * @returns {String} current refreshToken
   *
   */
  getRefreshToken() {
    return this.authentication.refreshToken;
  }

 /**
  * Gets authentication status from token. If autoUpdateToken === true,
  * updates token and returns true meanwhile
  *
  * @returns {Boolean} true: for Non-JWT tokens and unexpired JWT tokens, false: else
  *
  */
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

 /**
  * Gets exp from token payload and compares to current time
  *
  * @returns {Boolean | undefined} undefined: Non-JWT payload, true: unexpired JWT tokens, false: else
  *
  */
  isTokenExpired() {
    return this.authentication.isTokenExpired();
  }

  /**
  * Get payload from tokens
  *
  * @returns {null | String} null: Non-JWT payload, String: JWT token payload
  *
  */
  getTokenPayload() {
    return this.authentication.getPayload();
  }

  /**
   * Signup locally
   *
   * @param {String|{}}  displayName | object with signup data.
   * @param {[String]}   [email]
   * @param {[String]}   [password]
   *
   * @return {Promise<response>}
   *
   */
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
    return this.client.post(this.config.withBase(this.config.signupUrl), data)
      .then(response => {
        if (this.config.loginOnSignup) {
          this.authentication.setTokensFromResponse(response);
        }
        this.authentication.redirect(redirectUri, this.config.signupRedirect);

        return response;
      });
  }

  /**
   * login locally. Redirect depending on config
   *
   * @param {{}}  object with login data.
   *
   * @return {Promise<response>}
   *
   */
  login(email, password) {
    let content  = {};

    if (typeof arguments[1] !== 'string') {
      content = arguments[0];
    } else {
      console.warn('AuthService.login(email, password) is deprecated. Provide an object with login data instead.');
      content = {email: email, password: password};
    }

    return this._login(content);
  }

  _login(data, redirectUri) {
    if (this.config.clientId) {
      data.client_id = this.config.clientId;
    }

    return this.client.post(this.config.withBase(this.config.loginUrl), data)
      .then(response => {
        this.authentication.setTokensFromResponse(response);

        this.authentication.redirect(redirectUri, this.config.loginRedirect);

        return response;
      });
  }

  /**
   * logout locally and redirect to redirectUri (if set) or redirectUri of config
   *
   * @param {[String]}  [redirectUri]
   *
   * @return {Promise<>}
   *
   */
  logout(redirectUri) {
    return this.authentication.logout(redirectUri)
      .then(response => {
        this.authentication.redirect(redirectUri, this.config.logoutRedirect);

        return response;
      });
  }

  /**
   * update accessToken using the refreshToken
   *
   * @return {Promise<response>}
   *
   */
  updateToken() {
    this.isRefreshing  = true;
    const refreshToken = this.authentication.refreshToken;
    let content        = {};

    if (refreshToken) {
      content = {grant_type: 'refresh_token', refresh_token: refreshToken};
      if (this.config.clientId) {
        content.client_id = this.config.clientId;
      }

      return this.client.post(this.config.withBase(this.config.loginUrl), content)
          .then(response => {
            this.authentication.setTokensFromResponse(response);
            return response;
          }).catch(err => {
            this.authentication.removeTokens();
            throw err;
          })
          .then(response => {
            this.isRefreshing = false;
            return response;
          });
    }

    return Promise.reject('refreshToken not enabled');
  }

  /**
   * Authenticate with third-party and redirect to redirectUri (if set) or redirectUri of config
   *
   * @param {String}    name of the provider
   * @param {[String]}  [redirectUri]
   * @param {[{}]}      [userData]
   *
   * @return {Promise<response>}
   *
   */
  authenticate(name, redirectUri, userData = {}) {
    return this.authentication.authenticate(name, userData)
      .then(response => {
        this.authentication.setTokensFromResponse(response);

        this.authentication.redirect(redirectUri, this.config.loginRedirect);

        return response;
      });
  }

  /**
   * Unlink third-party
   *
   * @param {String}  name of the provider
   *
   * @return {Promise<response>}
   *
   */
  unlink(name, redirectUri) {
    const unlinkUrl = this.config.withBase(this.config.unlinkUrl) + name;
    return this.client.request(this.config.unlinkMethod, unlinkUrl)
      .then(response => {
        this.authentication.redirect(redirectUri);

        return response;
      });
  }
}

@inject(HttpClient, Config, AuthService, BaseConfig)
export class FetchConfig {
  /**
   * Construct the FetchConfig
   *
   * @param {HttpClient} httpClient
   * @param {Config} clientConfig
   * @param {Authentication} authService
   * @param {BaseConfig} config
   */
  constructor(httpClient, clientConfig, authService, config) {
    this.httpClient   = httpClient;
    this.clientConfig = clientConfig;
    this.authService  = authService;
    this.config       = config;
  }

  /**
   * Interceptor for HttpClient
   *
   * @return {{request: Function, response: Function}}
   */
  get interceptor() {
    return {
      request: request => {
        if (!this.config.httpInterceptor || !this.authService.isAuthenticated()) {
          return request;
        }
        let token = this.authService.getAccessToken();

        if (this.config.authTokenType) {
          token = `${this.config.authTokenType} ${token}`;
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
              token = `${this.config.authTokenType} ${token}`;
            }

            request.headers.set(this.config.authHeader, token);

            return this.client.fetch(request).then(resolve);
          });
        });
      }
    };
  }

  /**
   * Configure client(s) with authorization interceptor
   *
   * @param {HttpClient|Rest|string[]} (array of) httpClient, rest client or api endpoint names
   *
   * @return {HttpClient[]}
   */
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
        throw new Error(`There is no '${client || 'default'}' endpoint registered.`);
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
}

import './authFilter';

/**
 * Configure the plugin.
 *
 * @param {{globalResources: Function, container: {Container}}} aurelia
 * @param {{}|Function}                                         config
 */
function configure(aurelia, config) {
  aurelia.globalResources('./authFilter');

  const baseConfig = aurelia.container.get(BaseConfig);

  if (typeof config === 'function') {
    config(baseConfig);
  } else if (typeof config === 'object') {
    baseConfig.configure(config);
  }
  // after baseConfig was configured
  const fetchConfig  = aurelia.container.get(FetchConfig);
  const clientConfig = aurelia.container.get(Config);

  // Array? Configure the provided endpoints.
  if (Array.isArray(baseConfig.configureEndpoints)) {
    baseConfig.configureEndpoints.forEach(endpointToPatch => {
      fetchConfig.configure(endpointToPatch);
    });
  }

  let client;

  // Let's see if there's a configured named or default endpoint or a HttpClient.
  if (baseConfig.endpoint !== null) {
    if (typeof baseConfig.endpoint === 'string') {
      const endpoint = clientConfig.getEndpoint(baseConfig.endpoint);
      if (!endpoint) {
        throw new Error(`There is no '${baseConfig.endpoint || 'default'}' endpoint registered.`);
      }
      client = endpoint;
    } else if (baseConfig.endpoint instanceof HttpClient) {
      client = new Rest(baseConfig.endpoint);
    }
  }

  // No? Fine. Default to HttpClient. BC all the way.
  if (!(client instanceof Rest)) {
    client = new Rest(aurelia.container.get(HttpClient));
  }

  // Set the client on the config, for use throughout the plugin.
  baseConfig.client = client;
}

export {
  configure,
  FetchConfig,
  AuthService,
  AuthorizeStep
};
