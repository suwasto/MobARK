// M12 (V2) default hook: iOS ATS / certificate-pinning validators.
//
// Authorized-testing tooling only. Read-only observer at the
// NSURLSession/CFNetwork layer: logs when ATS policy is applied and when
// URLSession:didReceiveChallenge: (the certificate-pinning handshake)
// runs, plus CFNetwork's server-trust callback. No bypass here (M14/M15).
// Tag "pinning" groups these in the live feed.
//
// Event contract: send() a {source, tag, code, text} payload; the backend
// stamps ts/platform and fans it out (dynamic/events.py).

'use strict';

var SCRIPT_ID = "ios-pinning";

function report(message) {
  send({ source: "hook", tag: "pinning", code: SCRIPT_ID, text: message });
}

// ---- NSURLSession delegate pinning handshake ----
var Chal =
  ObjC.classes["NSURLAuthenticationChallenge"] ||
  ObjC.protocols["NSURLSessionDelegate"];

ObjC.chooseSync(ObjC.protocols["NSURLSessionDelegate"], {
  onMatch: function (delegate) {
    if (delegate.respondsToSelector("URLSession:didReceiveChallenge:completionHandler:")) {
      report("NSURLSession delegate handles didReceiveChallenge (certificate pinning)");
    }
    if (delegate.respondsToSelector("URLSession:didReceiveAuthenticationChallenge:")) {
      report("NSURLSession delegate handles authentication challenge");
    }
  },
  onComplete: function () {},
});

// ---- ATS: NSAppTransportSecurity ----
try {
  var ATS = ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey(
    "NSAppTransportSecurity"
  );
  report("NSAppTransportSecurity present: " + String(ATS));
} catch (e) {
  // ATS absent - report that explicitly (a legit finding, not an error).
  report("NSAppTransportSecurity not declared in Info.plist");
}

// ---- CFNetwork trust callback (CFURLRequestSetSSLCertContext era) ----
try {
  var SecTrust = ObjC.classes("SecTrust");
  if (SecTrust && SecTrust.respondsToSelector("evaluateWithError:")) {
    SecTrust["evaluateWithError:"].implementation = function (error) {
      var ret = this["evaluateWithError:"](error);
      report("SecTrust evaluateWithError: evaluated " + this.copyDescription());
      return ret;
    };
  }
} catch (e) {
  // skip - older SDK
}

report("iOS ATS / pinning observers installed");