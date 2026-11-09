# Mobile Application Security (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Specialized Domains. Premium room. Mobile app pentesting
  fundamentals: package structure, methodology, static analysis with **MobSF**, dynamic-analysis concepts,
  OWASP Mobile Top 10, and a static-analysis CTF (Leaky Package).
- **Date:** 2026-10-26.
- **Status:** SOLVED. All concept tasks + the Task 7 Leaky Package challenge answered.
- **Lab:** MobSF instance `MobSF-2026v3` at `<ip>` (web UI `http://MACHINE_IP:8000`, login
  `mobsf`/`mobsf`). Task files = `LeakyPackage.apk` (Android) + `LeakyPackage.ipa` (iOS), both from the
  Helix Solutions codebase. Task 7 answers are quoted verbatim in the room's own MobSF walkthrough
  screenshots, so no live scan was required to confirm them.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | File declaring permissions + component config | `Manifest` |
| 2 | Model isolating apps from each other | `Sandbox` |
| 3 | Number of pentest phases | `4` |
| 3 | Approach with full source + docs access | `White-box` |
| 4 | Open-source automated static-analysis tool | `MobSF` |
| 4 | OWASP category: hardcoded credentials in code | `Improper Credential Usage` (M1) |
| 5 | Tool to bypass SSL pinning | `Objection` |
| 5 | Attaching to a running app to observe/modify | `Runtime Instrumentation` |
| 6 | OWASP category: sensitive data in plain text | `Insecure Data Storage` (M9) |
| 6 | Binary check: detecting a modified device | `Root and Jailbreak Detection` |
| 7 | Hardcoded API key (Java) | `<redacted-secret>` |
| 7 | DB password (DatabaseHelper.java) | `<redacted-pw>` |
| 7 | Exported unprotected Activity | *(find it yourself)* |
| 7 | Info.plist key disabling ATS | `NSAllowsArbitraryLoads` |
| 7 | Sensitive value in internal_config.plist | `<redacted-secret>` |

Task 7 Q3 accepts multiple forms (`AdminPanelActivity` or the fully-qualified
`com.tryhackme.leakypackage.AdminPanelActivity`).

## Task 7 - Leaky Package findings (MobSF static analysis)

**Android `LeakyPackage.apk`** (`com.tryhackme.leakypackage`, security score 40/100):

- **Over-requested permissions** (5 dangerous): `ACCESS_FINE_LOCATION`, `CAMERA`, `READ_CONTACTS`,
  `READ_EXTERNAL_STORAGE`, `RECORD_AUDIO` on an internal employee portal -> **M8 Security Misconfiguration**.
- **Manifest flags:** `android:debuggable="true"` (HIGH - attach a debugger / dump heap via ADB) and
  `android:allowBackup="true"`.
- **Exported, unprotected Activity:** `com.tryhackme.leakypackage.AdminPanelActivity` has
  `android:exported="true"` and **no** `android:permission` -> any app on the device can launch it via an
  explicit intent, bypassing the normal auth flow. **M8**.
- **Hardcoded secrets** (Code Analysis flagged `HelixConfig.java` + `DatabaseHelper.java`) -> **M1**:
  - `HelixConfig.java`: `API_KEY = <redacted-secret>`,
    `INTERNAL_API_URL = http://internal.helixsolutions.local/api/v2`
  - `DatabaseHelper.java`: full prod DB conn - `DB_HOST=db.internal.helixsolutions.local`,
    `DB_NAME=helix_employee_portal`, `DB_USER=helix_admin`, `DB_PASSWORD=<redacted-pw>`, `DB_PORT=5432`
    (JDBC PostgreSQL). Host + name + root password = direct backend DB access.

**iOS `LeakyPackage.ipa`** (`com.tryhackme.LeakyPackage`, security score 45/100):

- **ATS disabled:** `Info.plist` -> `NSAppTransportSecurity` dict -> `NSAllowsArbitraryLoads = true`,
  letting the app talk plain **HTTP** to any server -> **M5 Insecure Communication** (+ M8).
- **Bundled secret:** `internal_config.plist` inside `LeakyPackage.app/` contains
  `internal_secret = <redacted-secret>` -> **M9 Insecure Data Storage**. `.plist` files ship
  readable inside the IPA, so any bundled token is trivially extractable.

## Key concepts

- **Package = binary + manifest/config + resources + assets.** Android manifest = `AndroidManifest.xml`;
  iOS equivalent = `Info.plist`. Both declare permissions, component config, and exported/internal status.
- **Four phases:** Reconnaissance -> Static analysis -> Dynamic analysis -> Reporting. Findings categorised
  with the **OWASP Mobile Top 10**.
- **Static analysis** (no execution): decompile (jadx/apktool), read manifest/Info.plist for
  over-requested permissions / exported components / insecure flags, grep for hardcoded secrets in code,
  string resources, config files, and bundled DBs/plists. **MobSF** automates this across both platforms.
- **Dynamic analysis** (running app): intercept traffic via proxy (unencrypted = **M5**); **SSL pinning**
  is a control, bypassed with **Objection** (built on **Frida**); **runtime instrumentation** = attach and
  hook/modify live (Frida) to bypass auth, dump memory; insecure logging of sensitive data = **M9**.
- **Testing approaches:** Black-box (no knowledge) / Grey-box (partial - most common) / White-box (full
  source + docs).
- **Binary protections (M7):** obfuscation, tamper detection, and **root/jailbreak detection** - absence of
  the last is itself a finding for banking/healthcare apps.
- **iOS ATS tell:** `NSAllowsArbitraryLoads=true` under `NSAppTransportSecurity` disables HTTPS enforcement.

## Lessons learned

- **MobSF is the one-stop static scanner for both APK and IPA.** Upload -> read Security Score, Permissions,
  Manifest/Transport Security Analysis, Code Analysis (hardcoded secrets), and Files/Possible Hardcoded
  Secrets. It surfaces the obvious issues fast so manual effort goes to logic flaws.
- **The highest-value mobile findings are static and pre-runtime:** hardcoded API keys / DB creds, exported
  components, and insecure flags (`debuggable`, `allowBackup`, `NSAllowsArbitraryLoads`) all fall out of
  the manifest/Info.plist + a decompile, before any device work.
- **Answer-blank lengths disambiguate the OWASP names:** `Improper Credential Usage` (8/10/5),
  `Insecure Data Storage` (8/4/7), `Root and Jailbreak Detection` (4/3/9/9).
- This room is static-analysis only; dynamic analysis (Objection/Frida) is conceptual here - hands-on comes
  in the follow-up Android/iOS rooms and **Mobile Malware Analysis**.

## Related

- [[specialized-domains-rooms]] - module tracker (this is the 5th Specialized Domains room written up).
- [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]].
