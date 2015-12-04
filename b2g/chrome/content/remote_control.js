/* -*- indent-tabs-mode: nil; js-indent-level: 2 -*- /
/* vim: set shiftwidth=2 tabstop=2 autoindent cindent expandtab: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

Cu.import("resource://gre/modules/Services.jsm");

const kPrefPresentationDiscoverable = "dom.presentation.discoverable";

(function setupRemoteControlSettings() {
  // To keep RemoteContorlService in the scope to prevent import again
  var remoteControlScope = {};

  function importRemoteControlService() {
    if (!("RemoteControlService" in remoteControlScope)) {
      Cu.import("resource://gre/modules/RemoteControlService.jsm", remoteControlScope);
    }
  }

  function setupRemoteControl() {
    if (Services.prefs.getBoolPref(kPrefPresentationDiscoverable)) {
      importRemoteControlService();
      remoteControlScope.RemoteControlService.start();
    } else {
      remoteControlScope.RemoteControlService.stop();
    }
  }

  Services.prefs.addObserver(kPrefPresentationDiscoverable, setupRemoteControl, false);

  setupRemoteControl();
})();