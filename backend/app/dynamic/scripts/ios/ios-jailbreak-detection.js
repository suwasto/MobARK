// M12 (V2) default hook: iOS jailbreak-detection checks.
//
// Authorized-testing tooling only. Read-only observer: logs the common
// jailbreak-detection entry points (canOpenURL: for detector apps, fork(0),
// and probes of jailbreak paths) so a tester can see whether the app runs
// a jailbreak check. No bypass here (M14/M15). Tag "jailbreak" groups
// these in the live feed.
//
// Event contract: send() a {source, tag, code, text} payload; the backend
// stamps ts/platform and fans it out (dynamic/events.py).

'use strict';

var SCRIPT_ID = "ios-jailbreak";

function report(message) {
  send({ source: "hook", tag: "jailbreak", code: SCRIPT_ID, text: message });
}

// ---- UIApplication canOpenURL: for jailbreak-detector apps ----
try {
  var JB_SCHEMES = /(cydia|cydia://|sileo|zbra|pkg|filza)/i;
  var UIApp = ObjC.classes.UIApplication;
  UIApp["canOpenURL:"].implementation = function (url) {
    var scheme = String(url).toLowerCase();
    var ret = this["canOpenURL:"](url);
    if (JB_SCHEMES.test(scheme)) {
      report("jailbreak scheme probe: " + scheme + " openable=" + ret);
    }
    return ret;
  };
} catch (e) {
  // skip
}

// ---- fork(0) (the classic jailbreak / sandbox probe) ----
try {
  Interceptor.attach(Module.getExportByName(null, "fork"), {
    onEnter: function () {
      report("fork(0) called (jailbreak / sandbox probe)");
    },
  });
} catch (e) {
  // skip
}

// ---- probes of suspicious jailbreak paths ----
try {
  var JB_PATHS = /(\/var\/lib\/dpkg|\/private\/var\/lib\/apt|frida|cydia|\.debf)/i;
  Interceptor.attach(Module.getExportByName(null, "open"), {
    onEnter: function (args) {
      var path = Memory.readUtf8String(args[0]) || "";
      if (JB_PATHS.test(path)) {
        report("path probe: " + path);
      }
    },
  });
} catch (e) {
  // skip
}

report("jailbreak-detection observers installed");