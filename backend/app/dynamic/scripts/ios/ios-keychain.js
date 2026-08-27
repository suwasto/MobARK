// M12 (V2) default hook: iOS Keychain access calls.
//
// Authorized-testing tooling only. Read-only observer: logs SecItemAdd /
// SecItemCopyMatching / SecItemUpdate / SecItemDelete (the Keychain API) so
// a tester can see what the app stores and reads from the Keychain and with
// which accessibility setting. No exfiltration or bypass here. Tag
// "keychain" groups these in the live feed.
//
// Event contract: send() a {source, tag, code, text} payload; the backend
// stamps ts/platform and fans it out (dynamic/events.py).

'use strict';

var SCRIPT_ID = "ios-keychain";

function report(message) {
  send({ source: "hook", tag: "keychain", code: SCRIPT_ID, text: message });
}

var SEC_ITEM_OPS = [
  ["SecItemAdd", "keychain add"],
  ["SecItemCopyMatching", "keychain read"],
  ["SecItemUpdate", "keychain update"],
  ["SecItemDelete", "keychain delete"],
];

SEC_ITEM_OPS.forEach(function (entry) {
  var name = entry[0];
  var label = entry[1];
  try {
    var addr = Module.getExportByName(null, name);
    Interceptor.attach(addr, {
      onEnter: function () {
        report(label + ": " + name + " called");
      },
    });
  } catch (e) {
    // SecItem not exported on this iOS - skip
  }
});

report("iOS Keychain access observers installed");