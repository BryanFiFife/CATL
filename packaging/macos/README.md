# macOS protected-mode blocker

The App Sandbox entitlements template has no network/file-system grants. It is **not** a usable sandboxed CATL app bundle or signed deployment. The new peer-authentication function calls `getpeereid` on AF_UNIX sockets and fails closed outside macOS. A real signed App Sandbox helper, secure socket directory, launchd profiles, application-group entitlement review, and Mac-host adversarial tests are still required. Do **not** treat `sandbox-exec` or the example XML file as proof of modern macOS containment.
