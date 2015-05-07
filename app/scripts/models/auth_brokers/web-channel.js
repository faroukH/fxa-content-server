/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A broker that makes use of the WebChannel abstraction to communicate
 * with the browser
 */

'use strict';

define([
  'underscore',
  'models/auth_brokers/oauth',
  'models/auth_brokers/mixins/channel',
  'lib/promise',
  'lib/channels/web'
], function (_, OAuthAuthenticationBroker, ChannelMixin, p, WebChannel) {

  var WebChannelAuthenticationBroker = OAuthAuthenticationBroker.extend({
    defaults: _.extend({}, OAuthAuthenticationBroker.prototype.defaults, {
      webChannelId: null
    }),

    initialize: function (options) {
      options = options || {};

      this._fxaClient = options.fxaClient;
      // channel can be passed in for testing.
      this._channel = options.channel;

      return OAuthAuthenticationBroker.prototype.initialize.call(this, options);
    },

    fetch: function () {
      var self = this;
      return OAuthAuthenticationBroker.prototype.fetch.call(this)
        .then(function () {
          if (self._isVerificationFlow()) {
            self._setupVerificationFlow();
          } else {
            self._setupSigninSignupFlow();
          }
        });
    },

    sendOAuthResultToRelier: function (result) {
      if (result.closeWindow !== true) {
        result.closeWindow = false;
      }

      // the WebChannel does not respond, create a promise
      // that immediately resolves.
      this.send('oauth_complete', result);
      return p();
    },

    /**
     * WebChannel reliers can request access to relier-specific encryption
     * keys.  In the future this logic may be lifted into the base OAuth class
     * and made available to all reliers, but we're putting it in this subclass
     * for now to guard against accidental exposure.
     *
     * If the relier indicates that they want keys, the OAuth result will
     * get an additional property 'keys', an object containing relier-specific
     * keys 'kAr' and 'kBr'.
     */

    getOAuthResult: function (account) {
      var self = this;
      return OAuthAuthenticationBroker.prototype.getOAuthResult.call(this, account)
        .then(function (result) {
          if (! self.relier.wantsKeys()) {
            return result;
          }
          var uid = account.get('uid');
          var keyFetchToken = account.get('keyFetchToken');
          var unwrapBKey = account.get('unwrapBKey');
          if (! keyFetchToken || ! unwrapBKey) {
            result.keys = null;
            return result;
          }
          return self._fxaClient.accountKeys(keyFetchToken, unwrapBKey)
            .then(function (keys) {
              return self.relier.deriveRelierKeys(keys, uid);
            })
            .then(function (keys) {
              result.keys = keys;
              return result;
            });
        });
    },

    afterSignIn: function (account) {
      return OAuthAuthenticationBroker.prototype.afterSignIn.call(
                this, account, { closeWindow: true });
    },

    beforeSignUpConfirmationPoll: function (account) {
      // If the relier wants keys, the signup verification tab will need
      // to be able to fetch them in order to complete the flow.
      // Send them as part of the oauth session data.
      if (this.relier.wantsKeys()) {
        this.session.set('oauth', _.extend({}, this.session.oauth, {
          keyFetchToken: account.get('keyFetchToken'),
          unwrapBKey: account.get('unwrapBKey')
        }));
      }
    },

    afterSignUpConfirmationPoll: function (account) {
      // The original tab can finish the OAuth flow if it is still open,
      // but not if the verification tab has already finished it.
      this.session.reload();
      if (this.session.oauth) {
        return this.finishOAuthFlow(account);
      }
      return p();
    },

    afterCompleteSignUp: function (account) {
      // The original tab may be closed, so the verification tab should
      // send the OAuth result to the browser to ensure the flow completes.
      // If the original tab is still open, there's a small chance that
      // it could complete the flow before we do.
      //
      // The slight delay here is to allow the functional tests time to
      // bind event handlers before the flow completes.
      var self = this;
      return p().delay(100).then(function () {
        self.session.reload();
        if (self.session.oauth) {
          if (self.relier.wantsKeys()) {
            account.set('keyFetchToken', self.session.oauth.keyFetchToken);
            account.set('unwrapBKey', self.session.oauth.unwrapBKey);
          }
          return self.finishOAuthFlow(account);
        }
      });
    },

    afterResetPasswordConfirmationPoll: function (account) {
      // The original tab can finish the OAuth flow if it is still open,
      // but not if the password reset tab has already finished it.
      this.session.reload();
      if (this.session.oauth) {
        return this.finishOAuthFlow(account);
      }
      return p();
    },

    afterCompleteResetPassword: function (account) {
      // The original tab may be closed, so the verification tab should
      // send the OAuth result to the browser to ensure the flow completes.
      // If the original tab is still open, there's a small chance that
      // it could complete the flow before we do.
      //
      // Since this tab had the password typed into it, there's no need
      // to try to retrieve a keyFetchToken from the session when the relier
      // wants keys.
      //
      // The slight delay here is to allow the functional tests time to
      // bind event handlers before the flow completes.
      var self = this;
      return p().delay(100).then(function () {
        self.session.reload();
        if (self.session.oauth) {
          return self.finishOAuthFlow(account);
        }
      });
    },

    // used by the ChannelMixin to get a channel.
    getChannel: function () {
      if (this._channel) {
        return this._channel;
      }

      var channel = new WebChannel(this.get('webChannelId'));
      channel.init({
        window: this.window
      });

      return channel;
    },

    _isVerificationFlow: function () {
      return !! this.getSearchParam('code');
    },

    _setupSigninSignupFlow: function () {
      this.importSearchParam('webChannelId');
    },

    _setupVerificationFlow: function () {
      var resumeObj = this.session.oauth;

      if (! resumeObj) {
        // user is verifying in a second browser. The browser is not
        // listening for messages.
        return;
      }

      this.set('webChannelId', resumeObj.webChannelId);
    }
  });

  _.extend(WebChannelAuthenticationBroker.prototype, ChannelMixin);
  return WebChannelAuthenticationBroker;
});
