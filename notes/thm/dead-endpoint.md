# Dead Endpoint (TryHackMe, Downtime Challenge 08)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 08 of 8 (Challenge 5 of 5, the finale). **Linux disk forensics + malware analysis + data recovery**.
  Difficulty: Hard.
- **Date:** 2026-10-24.
- **Status:** SOLVED. All 6 answers correct; +1 Tombstone raffle ticket (+90 team points). Completes the event
  at the **1950 max / 8 tickets**.
- **Lab:** in-browser Ubuntu analysis desktop at `<ip>` (SSH 22 + WebSockify VNC on 80). Evidence:
  `~/Desktop/artifacts/disk.img` (12 GB GPT disk) + `tools/` (Sleuth Kit, foremost, Ghidra, objdump, readelf,
  sqlite3, python3 `cryptography`). Worked **headless from the lab Terminal**; images read in `eom` at the end.

## Reconstructed incident (host `gallery`, app at `/srv/gallery`)

1. **Compromise - OS command injection (T1190 / T1059.004):** the Flask gallery (`gunicorn gallery:app`,
   `/srv/gallery/app/gallery.py`) exposes `POST /api/albums/<int:album_id>/export` (album forced to `1`, so the
   live path is the export endpoint *(find it yourself)*). Its worker builds a shell string with the attacker-controlled
   `selection` field and runs it with `shell=True`:
   ```python
   command = f"/bin/tar -cf '{destination}' -C '{ORIGINALS}' {selection}"
   subprocess.run(command, shell=True, ...)
   ```
   `selection` is unsanitised, so `"; <cmd> #"` style injection ran arbitrary commands as the `gallery` user
   and dropped/launched the ransomware.
2. **Encryptor (T1486):** **`/srv/gallery/.cache/.indexd`** - a stripped x86-64 PIE ELF, dynamically linked to
   `libcrypto.so.3`. SHA-256 `<redacted-hash>`. Guard checks:
   only runs if `gethostname()=="gallery"` and `geteuid()!=0`.
3. **Crypto - AES-256-GCM with a time-seeded key:**
   - Seed: `clock_gettime(CLOCK_REALTIME)` -> `seed = tv_sec*1000 + tv_nsec/1000000` = **Unix epoch in
     milliseconds** (13 digits). For this run *(find it yourself)* (around 2026-10-20 05:36:54 UTC).
   - Key: `state = seed`; the 32-byte AES key = **4 x splitmix64(state)** outputs stored little-endian
     (constants `0x9E3779B97F4A7C15` / `0xBF58476D1CE4E5B9` / `0x94D049BB133111EB`, shifts 30/27/31). One key
     reused for all three files; here `<redacted-hash>`.
   - Per file: fresh 12-byte IV from `RAND_bytes`, **28 bytes of AAD** = the file header (magic+ver+len+IV),
     then AES-256-GCM; output written as a `.jpg.locked` with this layout:
     ```
     0x00 "GPH1" | 0x04 ver=1 | 0x08 plaintext_len(LE,8) | 0x10 IV(12) | 0x1C tag(16) | 0x2C pad(4) | 0x30 ct
     ```
     It preserves each original's atime/mtime via `futimens` (so `.locked` mtime is NOT the encrypt time; the
     inode **ctime** is), then drops `RESTORE.txt`.
4. **Recovery:** the seed is a millisecond timestamp bounded tightly by the inode ctimes (`.indexd` .652,
   `.locked` .696, `RESTORE.txt` .743 - all 05:36:54). Brute-force the ~1000 ms candidates, regenerate the key
   with splitmix64, and let the stored **GCM tag** confirm the right one. Decrypting restored all three JPEGs;
   `yard_0152.jpg` is the North-yard inspection checklist carrying the flag.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Application endpoint abused for command execution | *(find it yourself)* |
| 2 | Full path of the encrypting executable | *(find it yourself)* |
| 3 | SHA-256 of that executable | `<redacted-hash>` |
| 4 | Encryption algorithm and mode | *(find it yourself)* |
| 5 | Initial seed value for the key | *(find it yourself)* |
| 6 | Flag in the recovered checklist | `THM{…}` |

## Method (headless, read-only)

```bash
# mount the rootfs READ-ONLY, no journal replay (no writes to the evidence)
mmls disk.img                                   # root partition = slot 008, start sector 2099200
OFF=$((2099200*512)); sudo mount -o ro,noload,loop,offset=$OFF disk.img /mnt/disk
# app + injection: /srv/gallery/app/gallery.py -> export_job() shell=True on 'selection'
# binary: file + sha256sum on /srv/gallery/.cache/.indexd (NEVER execute)
readelf -d indexd.elf | grep NEEDED             # libcrypto.so.3
objdump -T indexd.elf | grep -iE 'evp|rand'     # EVP_aes_256_gcm, RAND_bytes, clock_gettime
objdump -d -M intel indexd.elf                   # seed = epoch-ms; key = 4x splitmix64; AAD = header[0:28]
# recover offline with python3 cryptography: brute ms around the ctime second, GCM tag = oracle
#   key_from_seed(): state=seed; 4x splitmix64 -> 32-byte key (little-endian)
#   Cipher(AES(key),GCM(iv,tag)); authenticate_additional_data(file[:0x1c]); update(ct)+finalize()
eom yard_0152.jpg      # inspection checklist -> THM{…}
```

## Lessons learned

- **`shell=True` + f-string = command injection, every time.** The tell is an interpolated, user-controlled
  token inside a shell string (`{selection}` in `/bin/tar ... {selection}`). The ATT&CK map is the web route
  that reaches it, so answer with the *endpoint* *(find it yourself)*, not the shell. Read the route
  decorators and trace the request field to the `subprocess` call.
- **A "seed to generate the key" means recoverable crypto - find the seed source.** AES-256-GCM with a
  `RAND_bytes` key would be unbreakable; the imports gave it away - `clock_gettime` next to `RAND_bytes` meant
  the *key* was time-derived and the *IV* was the random part. When you see both, assume the time feeds the key.
- **splitmix64 is identifiable by its constants.** `0x9E3779B97F4A7C15` (the add), `0xBF58476D1CE4E5B9`,
  `0x94D049BB133111EB` with shifts 30/27/31 = textbook splitmix64. Recognise the constants and you can
  reimplement the keystream in a dozen lines of Python without touching Ghidra.
- **The GCM tag is a free brute-force oracle.** Epoch-ms seed over an unknown second is 1000 candidates;
  each either verifies (correct key) or raises `InvalidTag`. No need to know the exact millisecond - let
  `finalize()` tell you. Bound the second from the inode **ctime**, not mtime (the malware forged mtime with
  `futimens`, but ctime records the real rename/encrypt moment).
- **Do not forget the AAD.** GCM here authenticates the 28-byte header (magic+version+length+IV) as additional
  data before the plaintext. Omit `authenticate_additional_data(file[:0x1c])` and every tag check fails even
  with the right key - which would wrongly look like the wrong seed.
- **Read-only, never run.** `mount -o ro,noload` (skip journal replay) keeps the image pristine; Sleuth Kit /
  `objdump` / `strings` analyse the binary statically. The whole chain was solved without executing `.indexd`
  or writing to the evidence, exactly as the brief demanded.

## Related

- [[downtime-event]] - event tracker; **this is the 8th and final mission - event complete at 1950 / 8 tickets**.
- [[day-o]] - Challenge 06, the other malware-RE mission (there Windows memory + shellcode -> AES-CBC; here a
  Linux ELF ransomware -> AES-GCM). Both end in an AES-protected archive/image recovered offline with the key
  reconstructed from static analysis.
- [[the-waiting-room]] / [[handbook-for-the-recently-compromised]] / [[strange-and-unusual-activity]] - the
  other four challenges. [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
