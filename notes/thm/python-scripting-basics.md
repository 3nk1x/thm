# Python Scripting Basics module (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Python Scripting Basics**. Guided beginner Python module; the
  last stretch of the Jr Pen Tester path (path was at 88% going in). Four rooms:
  - **Python: Simple Demo** - DONE 2026-10-26
  - **Python: Core Concepts** - DONE 2026-10-26 (15/15)
  - **Python: Building Scripts** - DONE 2026-10-26 (15/15)
  - **Python: Pentesting Scripts** - 2026-10-26 (14/15; only Task 6 Q1 apollo.html MD5 cleartext pending)
- Kept as one module note (the rooms are tiny and tightly linked); each room is its own H2 section.

## Python: Simple Demo

- **Status:** SOLVED. Pure reading room (no lab needed) - builds a "Guess the Number" game across three
  drafts (`guess_v1/v2/v3.py` in `/home/ubuntu/Python-Demo`). All answers come straight from the task text.

### Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Function to display text on screen | *(find it yourself)* |
| 2 | Function to convert user input to integer | *(find it yourself)* |
| 3 | How Python writes "else if" | *(find it yourself)* |
| 3 | Output if user input is 50 | *(find it yourself)* |
| 4 | Type of loop used | *(find it yourself)* |
| 4 | Output on a correct guess in 3 tries | *(find it yourself)* |

(Blank lengths wanted the parenthesised `print()`/`int()`; plain `print`/`int` also name the function.)

### The finished game (guess_v3.py)

```python
import random

secret = random.randint(1, 20)   # 1 <= secret <= 20
tries = 0
guess = 0                        # sentinel: can never equal secret

print("I'm thinking of a number between 1 and 20")

while guess != secret:           # loop until correct
    text = input("Take a guess: ")
    guess = int(text)            # str -> int
    tries = tries + 1
    if guess < 1 or guess > 20:
        print("That number is out of range. Try again.")
    elif guess < secret:
        print("Too low, try again.")
    elif guess > secret:
        print("Too high, try again.")
    else:
        print("You got it in", tries, "tries!")
```

### Concepts

- **Variables:** `secret` (random target), `guess` (seeded to `0`, an impossible value so the loop runs at
  least once), `tries` (counter, `tries = tries + 1`). `random.randint(1, 20)` is inclusive on both bounds.
- **Conditionals:** `if` / `elif` / `elif` / `else` - Python evaluates top-down and runs the first true
  branch; the final `else` catches "equal to secret". Order matters (range check first, then low/high).
- **Iteration:** `while guess != secret:` repeats the indented block until the condition is false
  (`10 != 10` -> False -> exit). The `0` sentinel guarantees the first iteration.
- `input()` always returns a **string**; it must be `int()`-cast before numeric comparison.

## Python: Core Concepts

- **Status:** SOLVED (15/15). Part 1 of a two-room series with Building Scripts; covers data + control flow.
  Demo scripts in `/home/ubuntu/Core-Concepts/`.

### Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Built-in function revealing a value's data type | *(find it yourself)* |
| 2 | Type of `3.14` from `input()` before conversion | *(find it yourself)* |
| 2 | Last line printed by `fstrings_demo.py` | *(find it yourself)* |
| 3 | Function returning number of characters | *(find it yourself)* |
| 3 | `word[3:7]` where `word="TryHackMe"` | *(find it yourself)* |
| 3 | Method converting `"ADMIN"` to `"admin"` | *(find it yourself)* |
| 4 | Method adding an element to the end of a list | *(find it yourself)* |
| 4 | `services[80]` of `{22:"SSH",80:"HTTP"}` | *(find it yourself)* |
| 4 | Dict method retrieving a value with a safe fallback | *(find it yourself)* |
| 5 | Operator returning the remainder of a division | *(find it yourself)* |
| 5 | `10 // 3` | *(find it yourself)* |
| 5 | `2 ** 10` | *(find it yourself)* |
| 6 | Loop best for iterating each item in a list | *(find it yourself)* |
| 6 | `range(3)` produces | *(find it yourself)* |
| 6 | Keyword that immediately exits a loop | *(find it yourself)* |

### Concepts

- **Types + conversion:** `str`/`int`/`float`/`bool`/`list`; `type()` inspects, `int()`/`float()`/`str()`/
  `bool()` convert. `input()` always returns `str` - cast before arithmetic.
- **f-strings:** `f"User {username} on port {port}"` beats comma-print. Augmented assignment:
  `+= -= *= /=`.
- **Strings:** 0-indexed; `s[start:end]` excludes `end` (so `"TryHackMe"[3:7]` = `Hack`). Methods:
  `.upper/.lower/.strip/.replace/.split/.startswith/.endswith/.count`; char checks `.isdigit/.isupper/
  .isalpha/.isalnum` return bools (great inside `if`); `in` tests substring membership.
- **Lists** `[...]` (ordered, mutable): `.append/.remove/.pop/.sort/.reverse`, `len()`, `in`.
  **Dicts** `{k:v}`: index by key, `.keys/.values/.items`, and `.get(key, default)` to avoid KeyError.
- **Operators:** `**` exponent (`2**10`=1024), `//` floor div (`10//3`=3), `%` modulus (even test
  `n%2==0`). `in` / `not in` membership.
- **Loops:** `for x in seq` when count is known (lists, strings, `range(start,stop,step)`), `while cond`
  when it depends on runtime state. `range(3)` -> 0,1,2. `break` exits, `continue` skips to next iteration.
  Iterate dicts with `for k, v in d.items():`.

## Python: Building Scripts

- **Status:** SOLVED (15/15). Part 2 of the series; turns Core Concepts primitives into real programs.
  Capstone = a **Password Strength Checker**. Demo scripts in `/home/ubuntu/Building-Scripts/`.

### Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Keyword that sends a value back to the caller | *(find it yourself)* |
| 2 | `def scan(target, port=80)` - port when called `scan("<ip>")` | *(find it yourself)* |
| 2 | `score_password("TryHackMe2025!")` score | *(find it yourself)* |
| 3 | Exception from `int("hello")` | *(find it yourself)* |
| 3 | Exception opening a missing file | *(find it yourself)* |
| 3 | Exception from `10 / 0` | *(find it yourself)* |
| 4 | Keyword introducing a context manager | *(find it yourself)* |
| 4 | Method stripping the trailing newline | *(find it yourself)* |
| 4 | Passwords loaded from `common_passwords.txt` | *(find it yourself)* |
| 5 | Python's package manager | *(find it yourself)* |
| 5 | Module with `ascii_uppercase`/`digits`/`punctuation` | *(find it yourself)* |
| 5 | First char of SHA-256 hash (`imports_demo.py`) | *(find it yourself)* |
| 6 | Score if password is in the common list | *(find it yourself)* |
| 6 | Strength label for `TryHackMe!2025` | *(find it yourself)* |
| 6 | Asterisks logged for `TryHackMe!2025` | *(find it yourself)* |

### Why the computed ones hold

- **Task 2 Q3 = 5:** `score_password` adds 1 each for `len>=8`, `len>=12`, has-digit, has-upper, and
  not-in-common-list. `TryHackMe2025!` is 14 chars with digits + uppercase and is not a common password,
  so all five fire. (Only breaks if the demo's `common_list` literally contains it - it won't.)
- **Task 6 Q2/Q3:** `check_password("TryHackMe!2025")` scores `len>=8`, `len>=12`, uppercase, digit,
  punctuation = 5/5 -> `strength_labels[5]` = `Strong`. The log line masks the password with one `*` per
  character, and `TryHackMe!2025` = 14 chars = **14** asterisks.

### Concepts

- **Functions:** `def name(params):`; `return` hands a value back (no `return` -> `None`). *Parameter* =
  name in the def; *argument* = value passed in. Default params (`min_length=8`) are optional at call time.
  **Scope:** variables created inside a function are local and invisible outside it.
- **Error handling:** `try:` the risky op, `except <ExceptionType>:` to recover instead of crash. Common:
  `ValueError` (bad cast), `FileNotFoundError`, `ZeroDivisionError`, `KeyError`, `IndexError`. Stack
  multiple `except` blocks to handle each differently; `except Exception as e` is the catch-all (use
  sparingly - it hides bugs). The re-prompt pattern: `while True: try: ...; break / except ...: print(...)`.
- **File I/O:** always `with open(path, mode) as f:` (context manager auto-closes, even on error). Modes
  `"r"` read / `"w"` overwrite / `"a"` append - `"w"` erases an existing file, so append when preserving.
  Read via `.read()` / `.readline()` / `.readlines()` or loop `for line in f:`; `.strip()` each line to
  drop the trailing `\n`. Load a wordlist with `.append(line.strip())`, then test membership with `in`.
- **Libraries:** `import module`, `from module import name`, `import module as alias`. Standard library
  (no install): `os`, `sys`, `random`, `datetime`, `json`, `hashlib`, `string`. Third-party via **pip**
  (`pip install requests`) from PyPI. `string` supplies `ascii_uppercase`/`digits`/`punctuation` for
  character-variety checks. Pentest libs ahead (next room): `requests`, `scapy`, `pwntools`, `paramiko`,
  `beautifulsoup4`.
- **Capstone - Password Strength Checker:** `load_common_passwords()` (file I/O + `try/except`),
  `check_password()` returns a `(score, feedback)` tuple, `main()` loops with a `strength_labels` dict and
  `.get(score, "Unknown")` fallback, then appends a **masked** log line. Never log plaintext passwords.

## Python: Pentesting Scripts

- **Status:** 14/15 - 7 from the task text, 1 cracked offline, 6 from the live target (flag
  `THM{…}`); only Task 6 Q1 (apollo.html MD5 cleartext) is left to confirm. The
  capstone room -
  six security tools (web recon, ARP scan, port scan, downloader, hash cracker, SSH brute) + a menu toolkit.
  Scripts live in `/home/ubuntu/Pentesting-Scripts/` (also pulled to `C:\CTF\pentesting-scripts-room\` for
  offline work). `wordlist.txt` = 58 entries.
- **Ethics:** every technique is run only against the THM target (127.0.0.1 / MACHINE_IP). CFAA / CMA apply
  off-lab - signed SOW + RoE in real engagements.

### Answers

| Task | Question | Answer |
|---|---|---|
| 2 | `.html` pages found on port 8000 | *(find it yourself)* |
| 2 | Login page location | *(find it yourself)* |
| 3 | Scapy function: send at L2 + capture replies | *(find it yourself)* |
| 3 | Variable to change for interface `ens33` | *(find it yourself)* |
| 4 | socket method returning 0 on success (no exception) | *(find it yourself)* |
| 4 | Open ports under 10000 (count) | *(find it yourself)* |
| 4 | Top open port under 10000 | *(find it yourself)* |
| 5 | requests function to fetch + download the file | *(find it yourself)* |
| 5 | File mode avoiding binary corruption | *(find it yourself)* |
| 6 | Cleartext of MD5 on `apollo.html` (wordlist.txt) | *(pending - need the hash from apollo.html; 7 chars)* |
| 6 | Cleartext of SHA-256 `5030...cc60` (wordlist.txt) | *(find it yourself)* |
| 7 | Paramiko exception for rejected credentials | *(find it yourself)* |
| 7 | SSH password for `tester` | *(find it yourself)* |
| 7 | `flag.txt` contents | `THM{…}` |
| 8 | Structure mapping menu choices to functions | *(find it yourself)* |

### Cracked offline (Task 6 Q2)

*(find it yourself)* -> SHA-256 `<redacted-hash>`. Confirmed by
hashing every `wordlist.txt` entry with `hashlib.sha256` from `C:\CTF` (isolated: `python -I`, wordlist
passed as an argument, no import from the untrusted extract). The same approach cracks Task 6 Q1 the
instant the apollo.html MD5 string is in hand (the plaintext is one of the 58 wordlist entries).

### Concepts (the six tools)

- **Web recon (requests):** wordlist-driven HTTP probing. Subdomain enum prepends `sub.domain`; directory
  enum appends `/{entry}{ext}` and keeps any `status_code != 404` (200 found / 301 redirect / **403 =
  exists-but-forbidden**, valuable intel). `[line.strip() for line in f if line.strip()]` loads the list;
  `pass` on `ConnectionError`/`Timeout` so failures don't drown the hits.
- **ARP scan (Scapy):** Layer-2 discovery beats ICMP (a host can drop ping but must answer ARP). Build
  `Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=range)`, send with **`srp()`** (L2 send+receive), read `psrc`
  (IP) + Ether `src` (MAC). Needs `sudo`; `interface` defaults to `eth0` (change it for `ens33`).
- **Port scan (socket):** TCP connect scan via **`connect_ex()`** - returns `0` on open and raises no
  exception, so it's cheap at scale (vs `connect()`, which raises `OSError`). `AF_INET`/`SOCK_STREAM`,
  `settimeout`, `gethostbyname()` to resolve. `common_services` dict + `.get(port,"Unknown")` labels output.
- **Downloader (requests):** `requests.get(url, allow_redirects=True)` + `raise_for_status()`; write
  **`"wb"`** (binary - text mode corrupts images/archives). `stream=True` + `iter_content(8192)` for large
  files (constant memory). `os.makedirs(dir, exist_ok=True)`; filename = `url.split("/")[-1]` or `index.html`.
- **Hash cracker (hashlib):** dictionary attack - a hash isn't reversed, it's reproduced. Loop the wordlist
  line-by-line (constant memory), `hashlib.new(algo)` + `.update(text.encode())` + `.hexdigest()`, compare
  to `target.lower()`. `hashlib.new(algorithm)` makes it algo-agnostic (md5/sha1/sha256/sha512 via one arg).
  MD5 (128-bit)/SHA-1 are weak (GPU-fast, collisions); storage should use bcrypt/scrypt/Argon2 + salt.
- **SSH brute (Paramiko):** `SSHClient` + `AutoAddPolicy()`; `connect()` catches **`AuthenticationException`**
  (rejected = the expected case) separately from `SSHException`/`OSError` (protocol/network). Load the whole
  wordlist (network latency dominates, not memory). Beware account-lockout policies (3-5 failures).
- **Toolkit (Task 8):** menu-driven; a **dispatch dictionary** `{"1": run_subdomain_enum, ...}` maps input
  to function references (`actions[choice]()`) - cleaner/more extensible than an `if/elif` chain. Wrapper
  functions do the I/O and delegate to the reusable core; `int()` wrapped in `try/except` validates input.

### Live target findings (MACHINE_IP <ip>)

- **:8000 web root** serves 5 pages: `admin.html`, `private.html` (the login page), `apollo.html`,
  `surfer.html`, `index.html`. Each name is also a `wordlist.txt` entry - the dir enum only finds candidates
  that both exist on disk *and* are in the list.
- **Open ports** on MACHINE_IP: `22` (SSH), `80` (HTTP), `5901` (VNC), `8000` (HTTP), `8080` (HTTP). On
  `127.0.0.1` a 6th appears - `631` (CUPS) - because it binds to localhost only, a useful reminder that
  **what's reachable depends on the source address**.
- **SSH:** `tester:<redacted-pw>` (brute hit it on attempt 7/58).

### The last answer (Task 6 Q1) + the host-key lesson

- **Task 6 Q1 (still to confirm)** - `curl http://<ip>:8000/apollo.html` to reveal the MD5, then
  `python3 hash_cracker.py <hash> wordlist.txt`. The plaintext is a 7-char `wordlist.txt` entry; paste the
  hash and it cracks offline instantly.
- **Task 7 Q3 (solved) - host-key gotcha:** the manual `ssh tester@127.0.0.1` first failed with
  **"Host key verification failed"** because the VM's `known_hosts` still held an old key for 127.0.0.1
  (the box had been rebuilt since). Clear the stale entry, then the known-good `tester:<redacted-pw>` logs in:

  ```bash
  ssh-keygen -f ~/.ssh/known_hosts -R 127.0.0.1
  ssh tester@127.0.0.1      # password: <redacted-pw>
  cat flag.txt             # THM{…}
  ```

## Related

- [[tryhackme-learning-buddy]] / [[always-doc-rooms]]. Jr Pen Tester path context:
  [[specialized-domains-rooms]] (other Module work). [[ctf-workspace-dir]] for when the Pentesting Scripts
  room needs real targets.
