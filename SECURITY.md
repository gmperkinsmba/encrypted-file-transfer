# Security

Only transfers sent through the GitHub relay use AES-GCM. The same-device/local transfer path is plaintext. Received relay files are checked against their size and SHA-256 manifest before completion. On macOS, the app stores relay secrets in Keychain; settings files hold non-secret values. SHA-256 detects content changes when the expected value is trusted. It does not hide local files or encrypt the local transfer path.

Use your Mac’s disk encryption to protect saved files. The native app has an ad-hoc code signature. This lets the installer check whether its files changed. It does not prove who made the app. The build is not notarized.

Report security issues through [GitHub private vulnerability reporting](https://github.com/gmperkinsmba/encrypted-file-transfer/security/advisories/new).
