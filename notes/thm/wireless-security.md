# Wireless Security (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Specialized Domains -> Wireless Security. Knowledge/theory room
  (no attack box, no VPN target - 8 tasks, concepts + one interactive matching exercise).
- **Date:** 2026-10-23.
- **Status:** SOLVED - all task questions answered; Task 7 "Match the Attack" completed (6/6 correct pairs).
  Flag format `THM{…}` is revealed on completing the activity in-browser.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Process when a device connects to a wireless network | *(find it yourself)* |
| 2 | Multiple devices on same frequency degrading signal/coverage | *(find it yourself)* |
| 3 | Fake AP reusing a legit SSID to lure clients | *(find it yourself)* |
| 3 | Guest feature: connect via an 8-digit PIN | *(find it yourself)* |
| 3 | Of WPA2 / WPA3, resistant to offline dictionary attacks | *(find it yourself)* |
| 4 | Confirming a 6-digit code shown on both devices | *(find it yourself)* |
| 4 | Bluetooth frequency band | *(find it yourself)* |
| 4 | In-range theft of a phone's contacts/messages | *(find it yourself)* |
| 5 | Reading a badge and writing it to a blank card | *(find it yourself)* |
| 5 | Action on a lost badge | *(find it yourself)* |
| 6 | Smart lights + sensors on a low-power mesh to a hub | *(find it yourself)* |
| 6 | Of S0 / S2, vulnerable to key interception (all-zero key) | *(find it yourself)* |
| 7 | Flag from the matching activity | `THM{…}` (revealed on completion) |

## Task 7 - Match the Attack (6/6)

Each scenario maps to the technology whose attack it describes:

| Attack scenario | Technology |
|---|---|
| Remote-control signal recorded + replayed from outside a window, no auth | *(find it yourself)* |
| Reads an employee access badge, writes a blank card, opens the door | *(find it yourself)* |
| Captures the WPA2 4-way handshake, runs an offline dictionary attack | *(find it yourself)* |
| In range, pulls a victim's contacts/messages off their phone | *(find it yourself)* |
| Sniffs device pairing, recovers a key protected by a default value shared across all devices | *(find it yourself)* |
| Two relay devices forward comms between a contactless card and a shop terminal | *(find it yourself)* |

**The trap:** both "card" scenarios look similar - **employee badge / door entry = RFID**, **contactless
payment relay = NFC** (NFC is the 13.56 MHz subset used for payments/transit).

## Concept recap (for the exam / blue-team)

- **Wi-Fi identifiers:** SSID = network name; BSSID = the AP's MAC. Bands: 2.4 GHz (longer range ~45 m,
  penetrates walls, crowded, <=600 Mbps) vs 5 GHz (faster <=1300 Mbps, ~15 m, worse through obstacles).
- **Association** is the join step; **Open System Auth** verifies nothing (just "you can talk to me"), then
  WPA2-Personal proves the PSK via the **4-way handshake**, while WPA2-Enterprise (802.1X) hands off to a
  **RADIUS** server for per-user creds.
- **Wi-Fi attacks:** password cracking, **rogue AP** (unauthorised AP physically on the network) vs **evil
  twin** (standalone fake AP cloning the SSID), **deauth** (force disconnects), traffic interception.
  **WPA3** (SAE/Dragonfly) resists offline dictionary attacks that WPA2 PSK capture enables. Kill **WEP** and
  **WPS**; change default admin creds; segment guest nets; patch AP firmware.
- **Bluetooth:** 2.4 GHz. Classic (audio/files, SSP since 2.1) vs **BLE** (small/occasional data; "Just
  Works" pairing = no verification = MITM-able; LE Secure Connections since 4.2, Legacy Pairing on 4.0/4.1).
  Attacks: **Bluejacking** (unsolicited msgs), **Bluesnarfing** (steal data), **Bluebugging** (take control).
- **RFID vs NFC:** RFID up to 100 m+ (passive tag = powered by reader's field; active = own battery); **NFC =
  13.56 MHz, ~5 cm, two-way** (payments/transit/pairing). Risks: eavesdrop, **clone**, **relay** (defeats the
  distance limit), **skim**, lost/stolen cards. Defences: encrypted cards, tokenisation, instant
  revocation, Faraday sleeves, biometrics.
- **Other wireless / IoT:** **Zigbee** (low-power mesh; default-link-key sniffing at join - Philips Hue
  CVE-2020-6007), **Z-Wave** (**S0** all-zero key -> downgrade "Z-Shave"; use **S2** Diffie-Hellman), **LoRa**
  (km-range; ABP static keys -> frame-counter replay; prefer **OTAA**), **Cellular LTE-M/NB-IoT** (SIM auth
  but physical tamper + default-cred gateways), **Infrared** (no auth/encryption; NEC/RC5 replay or
  spec-crafted). Mitigations: Zigbee install codes, disable Z-Wave S0, LoRa OTAA, restrict cellular gateway
  mgmt, disable unused IR receivers, **segment IoT onto its own VLAN**.

## Lessons learned

- **Pure-theory room** - answered from the task text; no target to verify against empirically. Field widths
  (`_______`) confirm word lengths - count the underscores and match a candidate term of that length.
- **RFID vs NFC is the recurring gotcha:** access badges/door cards = **RFID**; tap-to-pay = **NFC** (a
  specific 13.56 MHz RFID flavour). The "relay" scenario is NFC payment; the "clone a badge" scenario is RFID.
- **Rogue AP != Evil Twin:** rogue = unauthorised AP wired *into* the target net; evil twin = standalone
  SSID-clone that relies on tricking users - no physical connection to the real network.
- **Z-Wave S0 = all-zeros key** is the memorable exam fact; S2 fixed it with DH but is downgradeable if
  backward-compat is left on.

## Related

- [[tryhackme-learning-buddy]] - study-buddy context.
- First room of the **Specialized Domains** module (after the AD module: see [[ad-module-plan]]).
