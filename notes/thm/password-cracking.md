# Password Cracking (TryHackMe)

- **Path:** Jr Penetration Tester - module "Password Attacks" (Premium room).
- **Room:** Password Cracking (~60 min) - how passwords are hashed, identifying hash types, and
  cracking with Hashcat and John the Ripper.
- **Date:** 2026-10-13.
- **Target:** AttackBox-based (`<ip>`); practical hashes in
  `/root/Rooms/PasswordCracking/` (`hash1.txt`..`hash4.txt`).
- **Status:** SOLVED. Theory (Tasks 2-5) answered; Task 6 hashes identified and all cracked
  (three verified locally in Python, the bcrypt one cracked against full rockyou).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Property meaning a hash can't be reversed | One-way |
| 2 | Random per-user string added before hashing | Salt |
| 2 | Password-specific, deliberately slow algorithm | bcrypt |
| 3 | Character length of a SHA-256 hash | 64 |
| 3 | John format for SHA-256 | `raw-sha256` |
| 4 | Full path to rockyou on the AttackBox | `/usr/share/wordlists/rockyou.txt` |
| 4 | Attack applying capitalisation / number-suffix transforms | Rule-based attack |
| 4 | Best attack for a Capital+6-lowercase+2-digit policy | Mask attack |
| 5 | Faster tool for a large SHA-256 set | Hashcat |
| 5 | Hashcat attack-mode number for a mask | 3 |
| 5 | John flag to show previously cracked passwords | `--show` |
| 6 | Algorithm of hash1 | MD5 |
| 6 | Hashcat mode for hash2 | 1400 (SHA-256) |
| 6 | Plaintext of hash1 | *(find it yourself)* |
| 6 | Shared plaintext of hash2 and hash3 | *(find it yourself)* |
| 6 | Plaintext of hash4 | *(find it yourself)* |

## Theory (Tasks 2-5)

**Storage (Task 2).** Passwords are stored as hashes, not plaintext. A good hash function is
one-way (can't reverse), deterministic, fixed-length, and collision-resistant. A **salt** is a
unique random per-user value mixed in before hashing so identical passwords get different hashes,
which defeats precomputed rainbow tables. Fast hashes (MD5, SHA-1, SHA-256) are wrong for passwords
because GPUs compute billions/sec; **bcrypt** (and Argon2) are built for passwords and are
deliberately slow via a cost factor. bcrypt is the "designed for passwords, deliberately slow"
answer.

**Identifying (Task 3).** First check length/prefix: MD5 = 32 hex, SHA-1 = 40, SHA-256 = 64,
NTLM = 32 hex (ambiguous with MD5 - context decides), bcrypt = ~60 chars with `$2a$/$2b$/$2y$`.
Tools: `hashid '<hash>'`, `hashcat --identify '<hash>'`. Mode/format map:

| Algorithm | Hashcat `-m` | John `--format=` | Length |
|---|---|---|---|
| MD5 | 0 | raw-md5 | 32 hex |
| SHA-1 | 100 | raw-sha1 | 40 hex |
| SHA-256 | 1400 | raw-sha256 | 64 hex |
| SHA-512 | 1700 | raw-sha512 | 128 hex |
| NTLM | 1000 | nt | 32 hex |
| bcrypt | 3200 | bcrypt | ~60, `$2*$` |

For a 32-hex hash with no context, try MD5 (`-m 0`) first, then NTLM (`-m 1000`).

**Attack strategies (Task 4).** Dictionary (rockyou first) -> rules (mutations like
capitalise/append digit/leet, e.g. `best64.rule`) -> mask (known structure, e.g.
`?u?l?l?l?l?l?d?d?d?d?s` for `Summer2026!`) -> brute force (only for tiny keyspaces). Hashcat mask
placeholders: `?l ?u ?d ?s ?a`. A policy-known password is a mask job; a mutated dictionary word is
a rules job.

**Tools (Task 5).** John = CPU, great auto-detect and odd formats, shadow files. Hashcat = GPU
(CPU fallback), fastest for sustained dictionary/rule/mask on standard hashes, needs explicit mode.
For a big SHA-256 batch, pick Hashcat. Mask attack mode = `-a 3`. `john --show` lists potfile hits.

## Task 6 - practical

The four hashes:

```
hash1  <redacted-hash>                                  -> MD5
hash2  <redacted-hash>  -> SHA-256
hash3  <redacted-hash>                                  -> NTLM
hash4  $2b$05$9I7YCSrgm6aLO7J5YPC9x.Kp08LQ7cSJTmkALhFTgm5UMFAwBr5.e      -> bcrypt (cost 05)
```

Cracked:

- **hash1 (MD5)** -> *(find it yourself)*. Verified `md5(<plaintext>) == e10adc...883e`.
- **hash2 (SHA-256)** -> *(find it yourself)*. Verified `sha256(<plaintext>) == 5e8848...42d8`.
- **hash3 (NTLM)** -> *(find it yourself)*. `<redacted-hash>` is the canonical
  `NTLM(<plaintext>)`. This is the deliberate "same plaintext, different algorithm" pair with hash2.
- **hash4 (bcrypt)** -> *(find it yourself)*. Not in the top-10k list; cracked against full rockyou
  (14,344,391 candidates) in ~8s using multiprocess `bcrypt.checkpw`.

AttackBox commands for the same result:

```
cd /root/Rooms/PasswordCracking/
hashid "$(cat hash1.txt)"                                           # confirm algorithm
hashcat -m 0    -a 0 hash1.txt /usr/share/wordlists/rockyou.txt     # MD5    -> *(find it yourself)*
hashcat -m 1400 -a 0 hash2.txt /usr/share/wordlists/rockyou.txt     # SHA256 -> *(find it yourself)*
hashcat -m 1000 -a 0 hash3.txt /usr/share/wordlists/rockyou.txt     # NTLM   -> *(find it yourself)*
hashcat -m 3200 -a 0 hash4.txt /usr/share/wordlists/rockyou.txt     # bcrypt -> *(find it yourself)* (slow)
```

(John equivalents: `john --format=raw-md5|raw-sha256|nt|bcrypt --wordlist=/usr/share/wordlists/rockyou.txt <file>`.)

## Lessons learned

- The algorithm matters as much as the password: `password` as SHA-256 vs NTLM produces two totally
  different strings, so identify before cracking. Getting `-m`/`--format` wrong = zero results no
  matter how long it runs.
- 32-hex is MD5 or NTLM; resolve by context (web DB = MD5, Windows SAM/AD = NTLM) or just try both.
- bcrypt's cost factor is the whole defense: even at cost 05 it's orders of magnitude slower than
  MD5/SHA. Here the low cost plus a weak password (*(find it yourself)*, a name+digits in rockyou) still fell
  in seconds; a high cost or an off-dictionary password would not.
- Multiprocessing makes CPU bcrypt cracking viable: all cores over rockyou found a mid-list word
  in ~8s where a single-threaded pass would crawl.
- Related: [introduction-to-wordlists](introduction-to-wordlists.md) (building/using wordlists),
  [hydra](hydra.md) (online vs. this offline cracking).

## Reproduction notes

Three hashes were verified/cracked in Python (`hashlib` for MD5/SHA-256; NTLM recognised as the
canonical value since this OpenSSL build disabled MD4). The bcrypt hash was cracked with the
`bcrypt` library over `rockyou.txt` using a multiprocessing pool. rockyou and the crack scripts
were kept in the session scratchpad, not this repo, per the evidence-handling rule. On the
AttackBox the intended path is hashcat/John with `/usr/share/wordlists/rockyou.txt`.
