// M12 (V2) default hook: Android root-detection calls.
//
// Authorized-testing tooling only. Read-only observer: it logs common root
// / tamper-detection entry points so a tester can see whether the app checks
// for root and what it probes. Root/BYPASS logic is not here (M14/M15). The
// tag "root" groups these in the live feed.
//
// Event contract: send() a {source, tag, code, text} payload; the backend
// stamps ts/platform and fans it out (dynamic/events.py).

'use strict';

var SCRIPT_ID = "android-root";
var ROOT_PATH_RE = /(su|Superuser|magisk|busybox|frida-server)/i;

function report(message) {
  send({ source: "hook", tag: "root", code: SCRIPT_ID, text: message });
}

Java.perform(function () {
  // ---- File.exists on common root/tamper paths ----
  try {
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      var ret = this.exists();
      if (ROOT_PATH_RE.test(path)) {
        report("root probe: " + path + " exists=" + ret);
      }
      return ret;
    };
  } catch (e) {
    // java.io.File always present - unreachable in practice.
  }

  // ---- Runtime.exec / ProcessBuilder for su-style commands ----
  try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      report("Runtime.exec: " + cmd);
      return this.exec(cmd);
    };
  } catch (e) {
    // skip
  }

  // ---- System.getProperty on the frida marker ----
  try {
    var Sys = Java.use("java.lang.System");
    Sys.getProperty.overload("java.lang.String").implementation = function (key) {
      var v = this.getProperty(key);
      if (String(key).toLowerCase().indexOf("frida") >= 0) {
        report("System.getProperty probe: " + key + "=" + v);
      }
      return v;
    };
  } catch (e) {
    // skip
  }

  report("Android root-detection observers installed");
});