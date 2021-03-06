/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// This module abstracts interaction with storage backends such as localStorage.

'use strict';

define([
  'lib/null-storage'
], function (NullStorage) {
  var NAMESPACE = '__fxa_storage';

  function fullKey (key) {
    return NAMESPACE + '.' + key;
  }

  function Storage (backend) {
    this._backend = backend || new NullStorage();
  }

  Storage.prototype.get = function (key) {
    var item;
    try {
      item = JSON.parse(this._backend.getItem(fullKey(key)));
    } catch (e) {
    }
    return item;
  };

  Storage.prototype.set = function (key, val) {
    this._backend.setItem(fullKey(key), JSON.stringify(val));
  };

  Storage.prototype.remove = function (key) {
    this._backend.removeItem(fullKey(key));
  };

  Storage.prototype.clear = function () {
    this._backend.clear();
  };

  Storage.prototype.isNull = function () {
    return this._backend instanceof NullStorage;
  };

  Storage.isLocalStorageEnabled = function (win) {
    var testData = 'local-storage-test';
    win = win || window;

    try {
      win.localStorage.setItem(testData, testData);
      win.localStorage.removeItem(testData);
      return true;
    } catch(e) {
      return false;
    }
  };

  Storage.factory = function (type, win) {
    var storage;
    win = win || window;

    if (type === 'localStorage' && this.isLocalStorageEnabled(win)) {
      storage = new Storage(win.localStorage);
    } else {
      storage = new Storage(new NullStorage());
    }

    return storage;
  };

  return Storage;
});
