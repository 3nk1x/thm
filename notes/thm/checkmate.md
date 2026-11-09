# Checkmate (Operation Checkmate) (TryHackMe)

- **Path:** Jr Penetration Tester - module "Password Attacks" (Premium room).
- **Room:** Checkmate - exploit weak password practices across Marco Bianchi's internal systems.
- **Date:** 2026-10-13.
- **Target:** `<ip>`. Services: main app `:5000`, firewall.thm `:5001`, jobs.thm `:5002`,
  social.thm `:5003`, SSH `:22`. (Hostnames resolve to the same IP; reach vhosts with a `Host:`
  header or `/etc/hosts`.)
- **Status:** SOLVED. All five level passwords recovered and each verified live (web logins and the
  final SSH). Worked from the Windows PC over the VPN with a Python client.
- **Rule:** blind brute-forcing the *main* app on `:5000` is out of scope and triggers a cooldown.
  The sub-services (5001/5002/5003/SSH) are the intended attack surface.

## Answers (Level passwords)

| Level | Service | Credential / value |
|---|---|---|
| 1 | firewall.thm:5001 (default creds) | `<redacted-pw>` (login `admin:<redacted-pw>`) |
| 2 | jobs.thm:5002 (company keyword) | `<redacted-pw>` (login `marco:<redacted-pw>`) |
| 3 | social.thm:5003 (bio-derived) | `<redacted-pw>` (login `marco:<redacted-pw>`) |
| 4 | social.thm profile-pic filename (SHA256) | *(find it yourself)* |
| 5 | SSH as marco (revealed pattern) | `<redacted-pw>` |

## Level 1 - default credentials (firewall.thm:5001)

FirewallOS management console. Tried common defaults against `POST /login`; `admin:<redacted-pw>` returned
a 302 redirect (success) while all others re-rendered the login page. The dashboard confirms it:
"Initial deployment completed with default admin credentials," and hints the next target
("Secure internal employee portal next"). **Password: `<redacted-pw>`.**

## Level 2 - company keyword (jobs.thm:5002)

Employee login at `POST /login`, username `marco`. The careers page is littered with company
keywords (innovation, excellence, security, digital, cloud, future, talent). Brute-forcing those
plus simple mutations, `marco:<redacted-pw>` returned 302 -> `/profile`. **Password: `<redacted-pw>`.**

The employee profile (`/profile`) leaks Marco's personal data, which feeds Level 3:

```
First name: Marco   Surname: Bianchi   Nickname: marky   Birthdate (DDMMYYYY): 14021995
```

## Level 3 - biographical password (social.thm:5003)

Login hint: "Use the details from jobs.thm to generate Marco's password." The intended tool is
**CUPP** (Common User Passwords Profiler): feed name Marco Bianchi, nickname marky, DOB 14/02/1995,
and it emits bio-based candidates. The working credential is **`marco:<redacted-pw>`** (verified:
302 redirect; a wrong password returns 200 with "Invalid credentials."). **Password: `<redacted-pw>`.**

Note: there is no username enumeration (every username yields the same "Invalid credentials."), and
`/login` is POST-only (GET returns 405; the form is served at `/`). A plain hand-rolled wordlist of
nickname+birthdate combos missed the real password `<redacted-pw>`; CUPP's combinatorics (surname + digit mash) is what
produces it, which is the lesson of the level.

## Level 4 - reverse the profile-picture filename (social.thm:5003)

Logged in, the feed shows Marco's avatar at
`/uploads/<redacted-hash>.png`. The platform
names uploads `SHA256(original_filename).png`, so recover the original filename by cracking that
SHA-256. Hashing a wordlist with image extensions, the match is a plain word *(find it yourself)* (no extension):

```
sha256("<redacted-answer>") = <redacted-hash>   # exact match
```

**Filename: *(find it yourself)*.** (Submit just the filename.)

## Level 5 - SSH with the revealed pattern (username marco)

Marco's own social post states his scheme: "I take a company keyword, capitalize it, then append
the year like 2024 or any other number and an exclamation mark," listing keywords security,
excellence, innovation, digital, cloud. So the pattern is `Capital<keyword><year>!`. Build a small
targeted list (keywords x {2024,2025,2023} x `!`) and SSH-brute as `marco`.
`marco:<redacted-pw>` authenticates (verified: `uid=1001(marco)` on host `tryhackme-2404`).
**Password: `<redacted-pw>`.**

Hydra equivalent (AttackBox):

```
# wordlist from the pattern
for k in Security Excellence Innovation Digital Cloud; do for y in 2024 2025 2023; do echo "$k$y!"; done; done > marco_ssh.txt
hydra -l marco -P marco_ssh.txt ssh://<ip> -t 4 -V
```

## Lessons learned

- The whole room is one theme: password reuse and predictable, human-chosen patterns across
  systems. Each level feeds the next (firewall -> employee portal -> personal data -> social ->
  SSH), which is how real lateral movement via credential reuse works.
- Level 1: always test vendor/default creds first; consoles deployed under time pressure keep them.
- Level 3: targeted bio wordlists (CUPP) beat generic lists and beat hand-rolled guesses - the real
  password `<redacted-pw>` was not an obvious nickname+DOB concatenation.
- Level 4: client-side "privacy" by hashing a *filename* is reversible; a filename has tiny entropy,
  so SHA-256 of it cracks instantly against a wordlist. Hash the input space, not the hash.
- Level 5: users broadcast their own password rules; one social post ("capital keyword + year + !")
  collapses the SSH keyspace to a few dozen candidates.
- Verify, don't trust: a supplied answer for Level 4 (`marcos_profile_pic.png`) did not hash to the
  avatar's value (and the supplied hash had a one-character typo, `d866` vs real `d86b`). Computing
  the hash settled it - the real filename is *(find it yourself)*.

## Related

- [password-cracking](password-cracking.md), [introduction-to-wordlists](introduction-to-wordlists.md),
  [hydra](hydra.md) - same credential-attack toolkit (CUPP/crunch wordlists, hashcat/John, Hydra SSH).
