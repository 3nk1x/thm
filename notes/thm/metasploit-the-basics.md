# Metasploit: The Basics

- **Path:** Jr Penetration Tester > Metasploit and Exploitation
- **Completed:** 2026-10-14
- **Scope:** TryHackMe training room; commands are for the authorised lab only.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Code that takes advantage of a flaw | Exploit |
| 2 | Code that runs after a successful exploit | Payload |
| 2 | Self-contained payload type | Singles |
| 2 | Symbol indicating a staged payload | `/` |
| 3 | Search all Apache exploit modules | `search type:exploit name:apache` |
| 3 | View module at index 3 | `info 3` |
| 3 | Return to the main prompt | `back` |
| 4 | Set LPORT to 6666 | `set LPORT 6666` |
| 4 | Set global RHOSTS | `setg RHOSTS <ip>` |
| 4 | Clear the selected payload | `unset PAYLOAD` |
| 4 | Launch an exploit module | `exploit` |
| 4 | Background a new session immediately | `-z` |
| 5 | Background a Meterpreter session | `background` |
| 5 | Interact with a session by ID | `-i` |
| 5 | Terminate session 2 | `sessions -k 2` |

## Core concepts

The vulnerability is the weakness, the exploit triggers it, and the payload runs after access is gained. A single payload is self-contained. A staged payload uses a slash between the payload type and connection method, for example `meterpreter/reverse_tcp`; an underscore indicates an inline or stageless form such as `meterpreter_reverse_tcp`.

## Msfconsole workflow

```text
msfconsole
search type:exploit name:apache
info 3
use <module-path>
show options
set RHOSTS <target-ip>
set LHOST <attackbox-ip>
set LPORT 6666
check
exploit -z
sessions -l
sessions -i 1
background
sessions -k 1
back
```

Use `setg` for values that should persist across modules, such as `RHOSTS` or `LHOST`. Use `set` for module-specific values. `unset all` resets the current module's options and `unsetg RHOSTS` clears a global value.

## Session management

`sessions -l` lists active sessions. `sessions -i <id>` enters one, `background` returns to `msf6 >` without closing it, and `sessions -k <id>` terminates one session. The uppercase `sessions -K` terminates every active session, so use it carefully.

## Validation

Answers and command syntax were checked against the room text on 2026-10-14. No target exploitation was performed for this introductory room.
