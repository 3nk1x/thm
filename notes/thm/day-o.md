# Day-O (TryHackMe, Downtime Challenge 06)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 06 of 8 (Challenge 3 of 5). **Memory forensics + malware analysis**. Difficulty: Medium.
- **Date:** 2026-10-23.
- **Status:** SOLVED. All 7 answers correct; +1 Tombstone raffle ticket (+90 team points).
- **Lab:** in-browser Ubuntu analysis desktop at `<ip>`. Evidence: `~/Desktop/artifacts/memory.mem`
  (4.37 GB Windows 10 19041 x64 dump) + `symbols/` + `tools/`. Volatility 3 (`vol`), Ghidra, Speakeasy,
  objdump, openssl. Worked **headless from the lab Terminal**.

## Reconstructed chain (victim `s.reyes`, capture 2026-10-05)

1. **User execution (T1204.002):** `s.reyes` ran **`ReviewClient.exe`** (32-bit / Wow64, PID 6260) from
   `\Users\s.reyes\Downloads\DocumentReview\`.
2. **Embedded payload (T1027.009):** the package's **`review-cover.png`** is a valid PNG with shellcode
   **appended after the `IEND` chunk** (sig `55 89 e5 83 ec 18` at offset `0x709d`, ~1345 bytes). Not
   steganography - an embedded blob.
3. **Injected region:** ReviewClient copied that shellcode into a private **`PAGE_EXECUTE_READWRITE`** page at
   **`0x8e0000`** (malfind tagged it "Function prologue") and executed it.
4. **Shellcode (32-bit PIC):** PEB walk (`fs:[0x30]` -> LDR -> module list), parsed kernel32's export table and
   resolved the API by name-compare, pushing `"WinExec"` on the stack (`push 0x63/0x6578/0x456e6957`). It then
   built an obfuscated stack-string command and called **`kernel32.WinExec`** (API hashing / dynamic
   resolution, T1027.007).
5. **Decoded stage (via Speakeasy emulation):**
   `WinExec("powershell.exe -NoProfile -EncodedCommand <base64>")`. The UTF-16LE base64 decodes to:
   ```powershell
   $k=[Convert]::FromBase64String('<redacted-secret>')
   $b=[IO.File]::ReadAllBytes('review-cache.dat')
   $a=[Security.Cryptography.Aes]::Create(); $a.Key=$k; $a.IV=$b[0..15]; $a.Mode='CBC'; $a.Padding='PKCS7'
   $d=$a.CreateDecryptor().TransformFinalBlock($b,16,$b.Length-16)
   [IO.File]::WriteAllBytes('review-cache.zip',$d)
   ```
6. **Payload goal:** AES-256-CBC decrypt `review-cache.dat` (key below, IV = its first 16 bytes) into
   `review-cache.zip`, containing `release/approval.txt` (the flag) + `release/contacts.csv` - staging the
   stolen NeuralNexus release approval.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Executable containing the payload | *(find it yourself)* |
| 2 | Start VA of its private executable region | *(find it yourself)* |
| 3 | File also containing the payload | *(find it yourself)* |
| 4 | Sub-technique for payload-in-PNG | *(find it yourself)* |
| 5 | API the payload calls for the next stage | *(find it yourself)* |
| 6 | Key the decoded stage uses on the cache | `<redacted-hash>` |
| 7 | Flag | `THM{…}` |

## Method (headless)

```bash
vol -f memory.mem windows.info                       # validate symbols (Win10 19041 x64)
vol -f memory.mem windows.malfind                     # RWX regions -> ReviewClient.e @ 0x8e0000 (Wow64)
vol -f memory.mem windows.pslist | grep ReviewClient  # PID 6260, Wow64=True
vol -f memory.mem windows.handles --pid 6260          # open file -> \Downloads\DocumentReview
vol -f memory.mem windows.filescan | grep DocumentReview   # review-cover.png / review-cache.dat / .exe
vol -f memory.mem windows.dumpfiles --virtaddr <off>  # dump the PNG + the .dat (DataSectionObject)
vol -f memory.mem windows.malfind --pid 6260 --dump   # dump the 0x8e0000 shellcode page
objdump -D -b binary -m i386 pid.6260.vad.*.dmp       # confirm PEB walk + WinExec stack-string
speakeasy -t pid.6260.vad.*.dmp -r -a x86             # EMULATE -> logs the WinExec("powershell -enc ..")
# decode -EncodedCommand (UTF-16LE base64) -> AES-256-CBC params
openssl enc -d -aes-256-cbc -K <keyhex> -iv <first16hex> -in ct.bin -out review-cache.zip
unzip review-cache.zip   # release/approval.txt -> THM{…}
```

## Lessons learned

- **malfind is noisy; triage the hits.** `WWAHost.exe` was Chakra **JIT** (a clean function prologue + bounds
  check) and `backgroundTaskHost` was zeroed heap + trampolines - both false positives. The real hit was a
  tiny one-page RWX region in a **Wow64 (32-bit)** app. The question's **8-hex address format** was the tell
  that the target was 32-bit; don't anchor on the first high-address 64-bit region.
- **Embedded payload != steganography.** Shellcode **appended after a PNG's `IEND`** is **T1027.009 Embedded
  Payloads**, not T1027.003 Steganography (which is data hidden in the pixels/LSBs). The grader distinguishes
  them; confirm *where* the bytes live (parse the chunks) before mapping ATT&CK.
- **Classic 32-bit PIC fingerprint:** `fs:[0x30]` PEB walk -> `+0xc`/`+0x14` module list -> PE export table
  (`+0x3c`,`+0x78`,`+0x24`) -> resolve API by name compare, with the API name pushed as a stack-string
  (`"WinExec"`). Recognise it and you know it's a shellcode loader before you emulate.
- **Emulate, don't hand-unXOR.** The command was a giant obfuscated stack-string; **Speakeasy**
  (`-r -a x86`) ran it and logged the fully decoded `WinExec("powershell -EncodedCommand ..")` in one shot.
  The provided tool existed for exactly this.
- **`dumpfiles` output is page-padded.** The `DataSectionObject` `.dat` for `review-cache.dat` was 4096 bytes
  but the real ciphertext was **528** (IV + 512). Strip trailing zeros and align to 16 before AES-CBC, or you
  get `bad decrypt`.
- **No pycryptodome? Use openssl.** `openssl enc -d -aes-256-cbc -K <hex> -iv <hex>` handles the AES-256-CBC +
  PKCS7 without any Python crypto module.

## Related

- [[downtime-event]] - event tracker (Challenge 06 of 8).
- [[the-waiting-room]] - Challenge 05; both chains end in an AES-CBC-protected blob (there RC4; here AES) and a
  staged `review-cache.*` archive. Same actor theme vs TryHatMe Studios / NeuralNexus.
- [[handbook-for-the-recently-compromised]] - Challenge 04. [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
