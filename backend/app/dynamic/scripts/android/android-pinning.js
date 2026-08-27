// M12 (V2) default hook: Android certificate/SSL pinning validators.
//
// Authorized-testing tooling only - run against an app you are allowed to
// test. This script does NOT bypass anything; it OBSERVES and logs. It hooks
// the common Android pinning verification points (TrustManagerImpl, OkHttp
// CertificatePinner, and the legacy HostnameVerifier) and reports a "hook"
// event for each call so a tester can see exactly when pinning validation
// runs and which endpoint it protects. Pinning-BYPASS scripts ship
// separately (M14/M15); keep this validator read-only.
//
// Event contract: each report() send()s a {source, tag, code, text} payload
// back to the backend, which stamps ts/platform and fans it out to the live
// feed (dynamic/events.py). The tag "pinning" groups these in the UI.

'use strict';

var SCRIPT_ID = "android-pinning";

function report(message) {
  send({ source: "hook", tag: "pinning", code: SCRIPT_ID, text: message });
}

Java.perform(function () {
  // ---- TrustManagerImpl.checkTrustedRecursive (the classic mTLS path) ----
  try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TMI.checkTrustedRecursive.implementation = function () {
      var ret = this.checkTrustedRecursive.apply(this, arguments);
      report("TrustManager.checkTrustedRecursive ran (HTTPS chain verification)");
      return ret;
    };
  } catch (e) {
    // Not on this Android version / stack - skip quietly.
  }

  // ---- OkHttp CertificatePinner.check ----
  try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.implementation = function (hostname, peerCerts) {
      report("OkHttp CertificatePinner verifying host: " + hostname);
      return this.check.apply(this, arguments);
    };
  } catch (e) {
    // okhttp not linked - nothing to hook, that's fine.
  }

  // ---- Legacy default HostnameVerifier ----
  try {
    var Https = Java.use("javax.net.ssl.HttpsURLConnection");
    var hv = Https.getDefaultHostnameVerifier();
    report("Default HostnameVerifier present: " + hv.getClass().getName());
  } catch (e) {
    // Not on this stack.
  }

  report("Android pinning validators installed");
});