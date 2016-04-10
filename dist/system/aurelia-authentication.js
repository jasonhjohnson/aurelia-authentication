'use strict';

System.register(['extend', 'aurelia-path', 'aurelia-dependency-injection', 'aurelia-router', 'aurelia-fetch-client', 'aurelia-api', './authFilter'], function (_export, _context) {
  var extend, parseQueryString, join, buildQueryString, inject, Redirect, HttpClient, Config, Rest, _dec, _class2, _dec2, _class3, _dec3, _class4, _dec4, _class5, _dec5, _class6, _dec6, _class7, _dec7, _class9, _typeof, _createClass, Popup, buildPopupWindowOptions, parseUrl, BaseConfig, Storage, OAuth1, OAuth2, camelCase, Authentication, AuthorizeStep, AuthService, FetchConfig;

  function _classCallCheck(instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  }

  function configure(aurelia, config) {
    aurelia.globalResources('./authFilter');

    var baseConfig = aurelia.container.get(BaseConfig);

    if (typeof config === 'function') {
      config(baseConfig);
    } else if ((typeof config === 'undefined' ? 'undefined' : _typeof(config)) === 'object') {
      baseConfig.configure(config);
    }

    var fetchConfig = aurelia.container.get(FetchConfig);
    var clientConfig = aurelia.container.get(Config);

    if (Array.isArray(baseConfig.configureEndpoints)) {
      baseConfig.configureEndpoints.forEach(function (endpointToPatch) {
        fetchConfig.configure(endpointToPatch);
      });
    }

    var client = void 0;

    if (baseConfig.endpoint !== null) {
      if (typeof baseConfig.endpoint === 'string') {
        var endpoint = clientConfig.getEndpoint(baseConfig.endpoint);
        if (!endpoint) {
          throw new Error('There is no \'' + (baseConfig.endpoint || 'default') + '\' endpoint registered.');
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

  return {
    setters: [function (_extend) {
      extend = _extend.default;
    }, function (_aureliaPath) {
      parseQueryString = _aureliaPath.parseQueryString;
      join = _aureliaPath.join;
      buildQueryString = _aureliaPath.buildQueryString;
    }, function (_aureliaDependencyInjection) {
      inject = _aureliaDependencyInjection.inject;
    }, function (_aureliaRouter) {
      Redirect = _aureliaRouter.Redirect;
    }, function (_aureliaFetchClient) {
      HttpClient = _aureliaFetchClient.HttpClient;
    }, function (_aureliaApi) {
      Config = _aureliaApi.Config;
      Rest = _aureliaApi.Rest;
    }, function (_authFilter) {}],
    execute: function () {
      _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) {
        return typeof obj;
      } : function (obj) {
        return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj;
      };

      _createClass = function () {
        function defineProperties(target, props) {
          for (var i = 0; i < props.length; i++) {
            var descriptor = props[i];
            descriptor.enumerable = descriptor.enumerable || false;
            descriptor.configurable = true;
            if ("value" in descriptor) descriptor.writable = true;
            Object.defineProperty(target, descriptor.key, descriptor);
          }
        }

        return function (Constructor, protoProps, staticProps) {
          if (protoProps) defineProperties(Constructor.prototype, protoProps);
          if (staticProps) defineProperties(Constructor, staticProps);
          return Constructor;
        };
      }();

      _export('Popup', Popup = function () {
        function Popup() {
          _classCallCheck(this, Popup);

          this.popupWindow = null;
          this.polling = null;
          this.url = '';
        }

        Popup.prototype.open = function open(url, windowName, options, redirectUri) {
          this.url = url;
          var optionsString = buildPopupWindowOptions(options || {});

          this.popupWindow = window.open(url, windowName, optionsString);

          if (this.popupWindow && this.popupWindow.focus) {
            this.popupWindow.focus();
          }

          return this;
        };

        Popup.prototype.eventListener = function eventListener(redirectUri) {
          var _this = this;

          return new Promise(function (resolve, reject) {
            _this.popupWindow.addEventListener('loadstart', function (event) {
              if (event.url.indexOf(redirectUri) !== 0) {
                return;
              }

              var parser = document.createElement('a');
              parser.href = event.url;

              if (parser.search || parser.hash) {
                var qs = parseUrl(parser);

                if (qs.error) {
                  reject({ error: qs.error });
                } else {
                  resolve(qs);
                }

                _this.popupWindow.close();
              }
            });

            _this.popupWindow.addEventListener('exit', function () {
              reject({ data: 'Provider Popup was closed' });
            });

            _this.popupWindow.addEventListener('loaderror', function () {
              reject({ data: 'Authorization Failed' });
            });
          });
        };

        Popup.prototype.pollPopup = function pollPopup() {
          var _this2 = this;

          return new Promise(function (resolve, reject) {
            _this2.polling = setInterval(function () {
              var errorData = void 0;

              try {
                if (_this2.popupWindow.location.host === document.location.host && (_this2.popupWindow.location.search || _this2.popupWindow.location.hash)) {
                  var qs = parseUrl(_this2.popupWindow.location);

                  if (qs.error) {
                    reject({ error: qs.error });
                  } else {
                    resolve(qs);
                  }

                  _this2.popupWindow.close();
                  clearInterval(_this2.polling);
                }
              } catch (error) {
                errorData = error;
              }

              if (!_this2.popupWindow) {
                clearInterval(_this2.polling);
                reject({
                  error: errorData,
                  data: 'Provider Popup Blocked'
                });
              } else if (_this2.popupWindow.closed) {
                clearInterval(_this2.polling);
                reject({
                  error: errorData,
                  data: 'Problem poll popup'
                });
              }
            }, 35);
          });
        };

        return Popup;
      }());

      _export('Popup', Popup);

      buildPopupWindowOptions = function buildPopupWindowOptions(options) {
        var width = options.width || 500;
        var height = options.height || 500;

        var extended = extend({
          width: width,
          height: height,
          left: window.screenX + (window.outerWidth - width) / 2,
          top: window.screenY + (window.outerHeight - height) / 2.5
        }, options);

        var parts = [];
        Object.keys(extended).map(function (key) {
          return parts.push(key + '=' + extended[key]);
        });

        return parts.join(',');
      };

      parseUrl = function parseUrl(url) {
        return extend(true, {}, parseQueryString(url.search), parseQueryString(url.hash));
      };

      _export('BaseConfig', BaseConfig = function () {
        function BaseConfig() {
          _classCallCheck(this, BaseConfig);

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
              nonce: function nonce() {
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

        BaseConfig.prototype.withBase = function withBase(url) {
          return join(this.baseUrl, url);
        };

        BaseConfig.prototype.configure = function configure(incomming) {
          for (var key in incomming) {
            var value = incomming[key];
            if (value !== undefined) {
              if (Array.isArray(value) || (typeof value === 'undefined' ? 'undefined' : _typeof(value)) !== 'object' || value === null) {
                this[key] = value;
              } else {
                extend(true, this[key], value);
              }
            }
          }
        };

        _createClass(BaseConfig, [{
          key: 'current',
          get: function get() {
            console.warn('BaseConfig.current() is deprecated. Use BaseConfig directly instead.');
            return this;
          }
        }, {
          key: 'authToken',
          set: function set(authToken) {
            console.warn('BaseConfig.authToken is deprecated. Use BaseConfig.authTokenType instead.');
            this._authTokenType = authToken;
            this.authTokenType = authToken;
            return authToken;
          },
          get: function get() {
            return this._authTokenType;
          }
        }, {
          key: 'responseTokenProp',
          set: function set(responseTokenProp) {
            console.warn('BaseConfig.responseTokenProp is deprecated. Use BaseConfig.accessTokenProp instead.');
            this._responseTokenProp = responseTokenProp;
            this.accessTokenProp = responseTokenProp;
            return responseTokenProp;
          },
          get: function get() {
            return this._responseTokenProp;
          }
        }, {
          key: 'tokenRoot',
          set: function set(tokenRoot) {
            console.warn('BaseConfig.tokenRoot is deprecated. Use BaseConfig.accessTokenRoot instead.');
            this._tokenRoot = tokenRoot;
            this.accessTokenRoot = tokenRoot;
            return tokenRoot;
          },
          get: function get() {
            return this._tokenRoot;
          }
        }, {
          key: 'tokenName',
          set: function set(tokenName) {
            console.warn('BaseConfig.tokenName is deprecated. Use BaseConfig.accessTokenName instead.');
            this._tokenName = tokenName;
            this.accessTokenName = tokenName;
            this.accessTokenStorage = this.tokenPrefix ? this.tokenPrefix + '_' + this.tokenName : this.tokenName;
            return tokenName;
          },
          get: function get() {
            return this._tokenName;
          }
        }, {
          key: 'tokenPrefix',
          set: function set(tokenPrefix) {
            console.warn('BaseConfig.tokenPrefix is deprecated. Use BaseConfig.accessTokenStorage instead.');
            this._tokenPrefix = tokenPrefix;
            this.accessTokenStorage = this.tokenPrefix ? this.tokenPrefix + '_' + this.tokenName : this.tokenName;
            return tokenPrefix;
          },
          get: function get() {
            return this._tokenPrefixx;
          }
        }]);

        return BaseConfig;
      }());

      _export('BaseConfig', BaseConfig);

      _export('Storage', Storage = (_dec = inject(BaseConfig), _dec(_class2 = function () {
        function Storage(config) {
          _classCallCheck(this, Storage);

          this.config = config;
        }

        Storage.prototype.get = function get(key) {
          if (window[this.config.storage]) {
            return window[this.config.storage].getItem(key);
          }
        };

        Storage.prototype.set = function set(key, value) {
          if (window[this.config.storage]) {
            return window[this.config.storage].setItem(key, value);
          }
        };

        Storage.prototype.remove = function remove(key) {
          if (window[this.config.storage]) {
            return window[this.config.storage].removeItem(key);
          }
        };

        return Storage;
      }()) || _class2));

      _export('Storage', Storage);

      _export('OAuth1', OAuth1 = (_dec2 = inject(Storage, Popup, BaseConfig), _dec2(_class3 = function () {
        function OAuth1(storage, popup, config) {
          _classCallCheck(this, OAuth1);

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

        OAuth1.prototype.open = function open(options, userData) {
          var _this3 = this;

          var provider = extend(true, {}, this.defaults, options);
          var serverUrl = this.config.withBase(provider.url);

          if (this.config.platform !== 'mobile') {
            this.popup = this.popup.open('', provider.name, provider.popupOptions, provider.redirectUri);
          }

          return this.config.client.post(serverUrl).then(function (response) {
            var url = provider.authorizationEndpoint + '?' + buildQueryString(response);

            if (_this3.config.platform === 'mobile') {
              _this3.popup = _this3.popup.open(url, provider.name, provider.popupOptions, provider.redirectUri);
            } else {
              _this3.popup.popupWindow.location = url;
            }

            var popupListener = _this3.config.platform === 'mobile' ? _this3.popup.eventListener(provider.redirectUri) : _this3.popup.pollPopup();

            return popupListener.then(function (result) {
              return _this3.exchangeForToken(result, userData, provider);
            });
          });
        };

        OAuth1.prototype.exchangeForToken = function exchangeForToken(oauthData, userData, provider) {
          var data = extend(true, {}, userData, oauthData);
          var serverUrl = this.config.withBase(provider.url);
          var credentials = this.config.withCredentials ? 'include' : 'same-origin';

          return this.config.client.post(serverUrl, data, { credentials: credentials });
        };

        return OAuth1;
      }()) || _class3));

      _export('OAuth1', OAuth1);

      _export('OAuth2', OAuth2 = (_dec3 = inject(Storage, Popup, BaseConfig), _dec3(_class4 = function () {
        function OAuth2(storage, popup, config) {
          _classCallCheck(this, OAuth2);

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

        OAuth2.prototype.open = function open(options, userData) {
          var _this4 = this;

          var provider = extend(true, {}, this.defaults, options);
          var stateName = provider.name + '_state';

          if (typeof provider.state === 'function') {
            this.storage.set(stateName, provider.state());
          } else if (typeof provider.state === 'string') {
            this.storage.set(stateName, provider.state);
          }

          var url = provider.authorizationEndpoint + '?' + buildQueryString(this.buildQuery(provider));
          var popup = this.popup.open(url, provider.name, provider.popupOptions, provider.redirectUri);
          var openPopup = this.config.platform === 'mobile' ? popup.eventListener(provider.redirectUri) : popup.pollPopup();

          return openPopup.then(function (oauthData) {
            if (provider.responseType === 'token' || provider.responseType === 'id_token%20token' || provider.responseType === 'token%20id_token') {
              return oauthData;
            }
            if (oauthData.state && oauthData.state !== _this4.storage.get(stateName)) {
              return Promise.reject('OAuth 2.0 state parameter mismatch.');
            }
            return _this4.exchangeForToken(oauthData, userData, provider);
          });
        };

        OAuth2.prototype.exchangeForToken = function exchangeForToken(oauthData, userData, provider) {
          var data = extend(true, {}, userData, {
            clientId: provider.clientId,
            redirectUri: provider.redirectUri
          }, oauthData);

          var serverUrl = this.config.withBase(provider.url);
          var credentials = this.config.withCredentials ? 'include' : 'same-origin';

          return this.config.client.post(serverUrl, data, { credentials: credentials });
        };

        OAuth2.prototype.buildQuery = function buildQuery(provider) {
          var _this5 = this;

          var query = {};
          var urlParams = ['defaultUrlParams', 'requiredUrlParams', 'optionalUrlParams'];

          urlParams.forEach(function (params) {
            (provider[params] || []).forEach(function (paramName) {
              var camelizedName = camelCase(paramName);
              var paramValue = typeof provider[paramName] === 'function' ? provider[paramName]() : provider[camelizedName];

              if (paramName === 'state') {
                paramValue = encodeURIComponent(_this5.storage.get(provider.name + '_state'));
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
        };

        return OAuth2;
      }()) || _class4));

      _export('OAuth2', OAuth2);

      camelCase = function camelCase(name) {
        return name.replace(/([\:\-\_]+(.))/g, function (_, separator, letter, offset) {
          return offset ? letter.toUpperCase() : letter;
        });
      };

      _export('Authentication', Authentication = (_dec4 = inject(Storage, BaseConfig, OAuth1, OAuth2), _dec4(_class5 = function () {
        function Authentication(storage, config, oAuth1, oAuth2) {
          _classCallCheck(this, Authentication);

          this.storage = storage;
          this.config = config;
          this.oAuth1 = oAuth1;
          this.oAuth2 = oAuth2;
        }

        Authentication.prototype.getLoginRoute = function getLoginRoute() {
          console.warn('Authentication.getLoginRoute is deprecated. Use baseConfig.loginRoute instead.');
          return this.config.loginRoute;
        };

        Authentication.prototype.getLoginRedirect = function getLoginRedirect() {
          console.warn('Authentication.getLoginRedirect is deprecated. Use baseConfig.loginRedirect instead.');
          return this.config.loginRedirect;
        };

        Authentication.prototype.getLoginUrl = function getLoginUrl() {
          console.warn('Authentication.getLoginUrl is deprecated. Use baseConfig.withBase(baseConfig.loginUrl) instead.');
          return this.config.withBase(this.config.loginUrl);
        };

        Authentication.prototype.getSignupUrl = function getSignupUrl() {
          console.warn('Authentication.getSignupUrl is deprecated. Use baseConfig.withBase(baseConfig.signupUrl) instead.');
          return this.config.withBase(this.config.signupUrl);
        };

        Authentication.prototype.getProfileUrl = function getProfileUrl() {
          console.warn('Authentication.getProfileUrl is deprecated. Use baseConfig.withBase(baseConfig.profileUrl) instead.');
          return this.config.withBase(this.config.profileUrl);
        };

        Authentication.prototype.getToken = function getToken() {
          console.warn('Authentication.getToken is deprecated. Use .accessToken instead.');
          return this.accessToken;
        };

        Authentication.prototype.getRefreshToken = function getRefreshToken() {
          console.warn('Authentication.getRefreshToken is deprecated. Use .refreshToken instead.');
          return this.refreshToken;
        };

        Authentication.prototype.getPayload = function getPayload() {
          var accessToken = this.accessToken;
          if (accessToken && accessToken.split('.').length === 3) {
            try {
              var base64Url = this.accessToken.split('.')[1];
              var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
              return JSON.parse(decodeURIComponent(escape(window.atob(base64))));
            } catch (e) {
              return null;
            }
          }
          return null;
        };

        Authentication.prototype.isTokenExpired = function isTokenExpired() {
          var payload = this.getPayload();
          var exp = payload && payload.exp;
          if (exp) {
            return Math.round(new Date().getTime() / 1000) > exp;
          }
          return undefined;
        };

        Authentication.prototype.isAuthenticated = function isAuthenticated() {
          if (!this.accessToken) {
            return false;
          }

          if (this.accessToken.split('.').length !== 3) {
            return true;
          }

          return this.isTokenExpired() !== true;
        };

        Authentication.prototype.getTokenFromResponse = function getTokenFromResponse(response, tokenProp, tokenName, tokenRoot) {
          if (!response) return null;

          var responseTokenProp = response[tokenProp];

          if (typeof responseTokenProp === 'string') {
            return responseTokenProp;
          }

          if ((typeof responseTokenProp === 'undefined' ? 'undefined' : _typeof(responseTokenProp)) === 'object') {
            var tokenRootData = tokenRoot && tokenRoot.split('.').reduce(function (o, x) {
              return o[x];
            }, responseTokenProp);
            return tokenRootData ? tokenRootData[tokenName] : responseTokenProp[tokenName];
          }

          return response[tokenName] === undefined ? null : response[tokenName];
        };

        Authentication.prototype.setAccessTokenFromResponse = function setAccessTokenFromResponse(response) {
          var config = this.config;
          var newToken = this.getTokenFromResponse(response, config.accessTokenProp, config.accessTokenName, config.accessTokenRoot);

          if (!newToken) throw new Error('Token not found in response');

          this.accessToken = newToken;
        };

        Authentication.prototype.setRefreshTokenFromResponse = function setRefreshTokenFromResponse(response) {
          var config = this.config;
          var newToken = this.getTokenFromResponse(response, config.refreshTokenProp, config.refreshTokenName, config.refreshTokenRoot);

          if (!newToken) throw new Error('Token not found in response');

          this.refreshToken = newToken;
        };

        Authentication.prototype.setTokensFromResponse = function setTokensFromResponse(response) {
          this.setAccessTokenFromResponse(response);

          if (this.config.useRefreshToken) {
            this.setRefreshTokenFromResponse(response);
          }
        };

        Authentication.prototype.removeTokens = function removeTokens() {
          this.accessToken = null;
          this.refreshToken = null;
        };

        Authentication.prototype.logout = function logout() {
          var _this6 = this;

          return new Promise(function (resolve) {
            _this6.removeTokens();

            resolve();
          });
        };

        Authentication.prototype.authenticate = function authenticate(name) {
          var userData = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

          var provider = this.config.providers[name].type === '1.0' ? this.oAuth1 : this.oAuth2;

          return provider.open(this.config.providers[name], userData);
        };

        Authentication.prototype.redirect = function redirect(redirectUrl, defaultRedirectUrl) {
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
        };

        _createClass(Authentication, [{
          key: 'accessToken',
          get: function get() {
            return this.storage.get(this.config.accessTokenStorage);
          },
          set: function set(newToken) {
            if (newToken) {
              return this.storage.set(this.config.accessTokenStorage, newToken);
            }
            return this.storage.remove(this.config.accessTokenStorage);
          }
        }, {
          key: 'refreshToken',
          get: function get() {
            return this.storage.get(this.config.refreshTokenStorage);
          },
          set: function set(newToken) {
            if (newToken) {
              return this.storage.set(this.config.refreshTokenStorage, newToken);
            }
            return this.storage.remove(this.config.refreshTokenStorage);
          }
        }]);

        return Authentication;
      }()) || _class5));

      _export('Authentication', Authentication);

      _export('AuthorizeStep', _export('AuthorizeStep', AuthorizeStep = (_dec5 = inject(Authentication), _dec5(_class6 = function () {
        function AuthorizeStep(authentication) {
          _classCallCheck(this, AuthorizeStep);

          this.authentication = authentication;
        }

        AuthorizeStep.prototype.run = function run(routingContext, next) {
          var isLoggedIn = this.authentication.isAuthenticated();
          var loginRoute = this.authentication.config.loginRoute;

          if (routingContext.getAllInstructions().some(function (i) {
            return i.config.auth;
          })) {
            if (!isLoggedIn) {
              return next.cancel(new Redirect(loginRoute));
            }
          } else if (isLoggedIn && routingContext.getAllInstructions().some(function (i) {
            return i.fragment === loginRoute;
          })) {
            return next.cancel(new Redirect(this.authentication.config.loginRedirect));
          }

          return next();
        };

        return AuthorizeStep;
      }()) || _class6)));

      _export('AuthorizeStep', AuthorizeStep);

      _export('AuthService', _export('AuthService', AuthService = (_dec6 = inject(Authentication, BaseConfig), _dec6(_class7 = function () {
        function AuthService(authentication, config) {
          _classCallCheck(this, AuthService);

          this.isRefreshing = false;

          this.authentication = authentication;
          this.config = config;
        }

        AuthService.prototype.getMe = function getMe(criteria) {
          if (typeof criteria === 'string' || typeof criteria === 'number') {
            criteria = { id: criteria };
          }
          return this.client.find(this.config.withBase(this.config.profileUrl), criteria);
        };

        AuthService.prototype.updateMe = function updateMe(body, criteria) {
          if (typeof criteria === 'string' || typeof criteria === 'number') {
            criteria = { id: criteria };
          }
          return this.client.update(this.config.withBase(this.config.profileUrl), criteria, body);
        };

        AuthService.prototype.getAccessToken = function getAccessToken() {
          return this.authentication.accessToken;
        };

        AuthService.prototype.getCurrentToken = function getCurrentToken() {
          console.warn('AuthService.getCurrentToken() is deprecated. Use .getAccessToken() instead.');
          return this.getAccessToken();
        };

        AuthService.prototype.getRefreshToken = function getRefreshToken() {
          return this.authentication.refreshToken;
        };

        AuthService.prototype.isAuthenticated = function isAuthenticated() {
          var isExpired = this.authentication.isTokenExpired();
          if (isExpired && this.config.autoUpdateToken) {
            if (this.isRefreshing) {
              return true;
            }
            this.updateToken();
          }
          return this.authentication.isAuthenticated();
        };

        AuthService.prototype.isTokenExpired = function isTokenExpired() {
          return this.authentication.isTokenExpired();
        };

        AuthService.prototype.getTokenPayload = function getTokenPayload() {
          return this.authentication.getPayload();
        };

        AuthService.prototype.signup = function signup(displayName, email, password) {
          var content = void 0;

          if (_typeof(arguments[0]) === 'object') {
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
        };

        AuthService.prototype._signup = function _signup(data, redirectUri) {
          var _this7 = this;

          return this.client.post(this.config.withBase(this.config.signupUrl), data).then(function (response) {
            if (_this7.config.loginOnSignup) {
              _this7.authentication.setTokensFromResponse(response);
            }
            _this7.authentication.redirect(redirectUri, _this7.config.signupRedirect);

            return response;
          });
        };

        AuthService.prototype.login = function login(email, password) {
          var content = {};

          if (typeof arguments[1] !== 'string') {
            content = arguments[0];
          } else {
            console.warn('AuthService.login(email, password) is deprecated. Provide an object with login data instead.');
            content = { email: email, password: password };
          }

          return this._login(content);
        };

        AuthService.prototype._login = function _login(data, redirectUri) {
          var _this8 = this;

          if (this.config.clientId) {
            data.client_id = this.config.clientId;
          }

          return this.client.post(this.config.withBase(this.config.loginUrl), data).then(function (response) {
            _this8.authentication.setTokensFromResponse(response);

            _this8.authentication.redirect(redirectUri, _this8.config.loginRedirect);

            return response;
          });
        };

        AuthService.prototype.logout = function logout(redirectUri) {
          var _this9 = this;

          return this.authentication.logout(redirectUri).then(function (response) {
            _this9.authentication.redirect(redirectUri, _this9.config.logoutRedirect);

            return response;
          });
        };

        AuthService.prototype.updateToken = function updateToken() {
          var _this10 = this;

          this.isRefreshing = true;
          var refreshToken = this.authentication.refreshToken;
          var content = {};

          if (refreshToken) {
            content = { grant_type: 'refresh_token', refresh_token: refreshToken };
            if (this.config.clientId) {
              content.client_id = this.config.clientId;
            }

            return this.client.post(this.config.withBase(this.config.loginUrl), content).then(function (response) {
              _this10.authentication.setTokensFromResponse(response);
              return response;
            }).catch(function (err) {
              _this10.authentication.removeTokens();
              throw err;
            }).then(function (response) {
              _this10.isRefreshing = false;
              return response;
            });
          }

          return Promise.reject('refreshToken not enabled');
        };

        AuthService.prototype.authenticate = function authenticate(name, redirectUri) {
          var _this11 = this;

          var userData = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

          return this.authentication.authenticate(name, userData).then(function (response) {
            _this11.authentication.setTokensFromResponse(response);

            _this11.authentication.redirect(redirectUri, _this11.config.loginRedirect);

            return response;
          });
        };

        AuthService.prototype.unlink = function unlink(name, redirectUri) {
          var _this12 = this;

          var unlinkUrl = this.config.withBase(this.config.unlinkUrl) + name;
          return this.client.request(this.config.unlinkMethod, unlinkUrl).then(function (response) {
            _this12.authentication.redirect(redirectUri);

            return response;
          });
        };

        _createClass(AuthService, [{
          key: 'client',
          get: function get() {
            return this.config.client;
          }
        }, {
          key: 'auth',
          get: function get() {
            console.warn('AuthService.auth is deprecated. Use .authentication instead.');
            return this.authentication;
          }
        }]);

        return AuthService;
      }()) || _class7)));

      _export('AuthService', AuthService);

      _export('FetchConfig', _export('FetchConfig', FetchConfig = (_dec7 = inject(HttpClient, Config, AuthService, BaseConfig), _dec7(_class9 = function () {
        function FetchConfig(httpClient, clientConfig, authService, config) {
          _classCallCheck(this, FetchConfig);

          this.httpClient = httpClient;
          this.clientConfig = clientConfig;
          this.authService = authService;
          this.config = config;
        }

        FetchConfig.prototype.configure = function configure(client) {
          var _this13 = this;

          if (Array.isArray(client)) {
            var _ret = function () {
              var configuredClients = [];
              client.forEach(function (toConfigure) {
                configuredClients.push(_this13.configure(toConfigure));
              });

              return {
                v: configuredClients
              };
            }();

            if ((typeof _ret === 'undefined' ? 'undefined' : _typeof(_ret)) === "object") return _ret.v;
          }

          if (typeof client === 'string') {
            var endpoint = this.clientConfig.getEndpoint(client);
            if (!endpoint) {
              throw new Error('There is no \'' + (client || 'default') + '\' endpoint registered.');
            }
            client = endpoint.client;
          } else if (client instanceof Rest) {
            client = client.client;
          } else if (!(client instanceof HttpClient)) {
            client = this.httpClient;
          }

          client.interceptors.push(this.interceptor);

          return client;
        };

        _createClass(FetchConfig, [{
          key: 'interceptor',
          get: function get() {
            var _this14 = this;

            return {
              request: function request(_request) {
                if (!_this14.config.httpInterceptor || !_this14.authService.isAuthenticated()) {
                  return _request;
                }
                var token = _this14.authService.getAccessToken();

                if (_this14.config.authTokenType) {
                  token = _this14.config.authTokenType + ' ' + token;
                }

                _request.headers.set(_this14.config.authHeader, token);

                return _request;
              },
              response: function response(_response, request) {
                return new Promise(function (resolve, reject) {
                  if (_response.ok) {
                    return resolve(_response);
                  }
                  if (_response.status !== 401) {
                    return resolve(_response);
                  }
                  if (!_this14.config.httpInterceptor || !_this14.authService.isTokenExpired()) {
                    return resolve(_response);
                  }
                  if (!_this14.config.useRefreshToken || !_this14.authService.getRefreshToken()) {
                    return resolve(_response);
                  }

                  _this14.authService.updateToken().then(function () {
                    var token = _this14.authService.getAccessToken();

                    if (_this14.config.authTokenType) {
                      token = _this14.config.authTokenType + ' ' + token;
                    }

                    request.headers.set(_this14.config.authHeader, token);

                    return _this14.client.fetch(request).then(resolve);
                  });
                });
              }
            };
          }
        }]);

        return FetchConfig;
      }()) || _class9)));

      _export('FetchConfig', FetchConfig);

      _export('configure', configure);

      _export('FetchConfig', FetchConfig);

      _export('AuthService', AuthService);

      _export('AuthorizeStep', AuthorizeStep);
    }
  };
});