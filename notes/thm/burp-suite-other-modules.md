# Burp Suite: Other Modules (TryHackMe)

- **Path:** Jr Penetration Tester > Burp Suite module (room 4 of 5)
- **Completed:** 2026-10-09 - **Target:** <ip> (Bastion Hosting)
- **Tool:** Burp Suite Community v2026.3.3. Encoding/hashing answers cross-checked with Python.

The lesser-known tabs: **Decoder** (encode/decode/hash), **Comparer** (diff two blobs),
**Sequencer** (token randomness/entropy), **Organizer** (save/annotate requests). Any module can
feed these via right-click Send to Decoder/Comparer/Sequencer/Organizer.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Feature that auto-decodes input | *(find it yourself)* |
| 3 | base64 of `Let's Start Simple.` | *(find it yourself)* |
| 3 | URL-decode `%4e...%67` | *(find it yourself)* |
| 3 | Smart-decode `&#x25;&#x33;&#x34;&#x25;&#x33;&#x37;` | *(find it yourself)* |
| 3 | `Encoding Challenge` base64 > ASCII Hex > octal | <redacted-hash> |
| 4 | SHA-256 of `Let's get Hashing!` (hex) | <redacted-hash> |
| 4 | MD4 of `Insecure Algorithms` (base64) | *(find it yourself)* |
| 4 | SSH key matching MD5 <redacted-hash> | *(find it yourself)* |
| 7 | What Sequencer evaluates | *(find it yourself)* |
| 8 | Overall quality of randomness | *(find it yourself)* |
| 10 | Saved requests read-only? | *(find it yourself)* |

(Tasks 1, 5, 6, 9, 11 need no answer.)

## Decoder
- Encode/Decode menus: Plain, URL, HTML, Base64, ASCII Hex, Hex/Octal/Binary (numeric), Gzip.
  Transformations stack (e.g. base64 then ASCII Hex then Octal). Each is colour-coded.
- Smart Decode = recursive auto-decode (like CyberChef Magic). Example: `&#x25;&#x33;&#x34;...` is
  HTML entities -> `%34%37` -> URL-decodes to the final value *(find it yourself)*.
- Hash dropdown = generate a hashsum (long list of algos). Output is raw bytes (Hex view); apply
  ASCII Hex for the familiar hex string, or Base64 for a base64 form.
- Decoder intermediates for the octal challenge: base64 `RW5jb2RpbmcgQ2hhbGxlbmdl`,
  ASCII Hex `<redacted-hash>`, then Octal.
- Task 4c method: `wget http://<ip>:9999/AlteredKeys.zip`, extract, MD5 each of key1..key4,
  the one matching the given hash is the real key *(find it yourself)*. (Hashing verifies file integrity: the altered keys all
  have different hashes; only the real one matches.)

## Comparer
Diff two datasets by Words or Bytes; Send to Comparer from any module. Use case: compare a failed
vs successful login response to see what differs (ties to the Intruder "sort by length" trick).

## Sequencer
Evaluates token entropy/randomness (session cookies, CSRF/anti-bruteforce tokens). Live Capture
replays a request thousands of times, collecting the token, then analyses. Here the admin
loginToken (Form field) scored effective entropy ~117 bits = overall quality *(find it yourself)* = securely
generated and not predictable. Weakly-generated tokens could be predicted (bad for password resets,
sessions).

## Organizer
Stores read-only copies of interesting requests for later / reporting. Send to Organizer (Ctrl+O).

## Lessons
- Decoder replaces alt-tabbing to CyberChef for quick encode/decode/hash during testing; Smart
  Decode is the fast "what is this blob" button.
- Hashing is one-way and integrity-sensitive: one changed byte = totally different hash (how we
  picked the real SSH key out of four look-alikes).
- Token entropy matters: predictable session/CSRF/reset tokens are a real vulnerability; Sequencer
  is how you measure it. ~117 bits here = secure.
- MD5/MD4 are deprecated for security use (collisions), fine only for non-security integrity checks.
