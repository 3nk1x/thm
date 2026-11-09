# Burp Suite: Extensions (TryHackMe)

- **Path:** Jr Penetration Tester > Burp Suite module (room 5 of 5, module COMPLETE)
- **Completed:** 2026-10-09 - No lab machine (theory only). Burp Community v2026.3.3.

How to extend Burp with add-ons: the Extensions interface, the BApp Store, Jython for Python
extensions, and the extension API.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Extensions invoked in ascending (A) or descending (D) order | *(find it yourself)* |

(Tasks 1, 3, 4, 5, 6 need no answer.)

## Notes
- **Extensions interface:** list of loaded extensions (toggle on/off per project); Add (load an
  extension from disk), Remove, Up/Down (ordering). Order matters: extensions run top-to-bottom,
  so one that rewrites a request affects what later ones see. Per-extension Details /
  Output / Errors panes at the bottom (Errors is where you debug a misbehaving extension).
- **BApp Store:** built-in marketplace of vetted extensions. Example install: Request Timer (Java,
  by Nick Taylor) - logs per-request response time, useful for time-based attacks (e.g. a login
  that takes longer for a valid username = username enumeration). Some extensions add a top-menu
  tab, some add right-click menu items.
- **Jython:** Python extensions are not native. Point Burp at the Jython standalone JAR (Extensions
  settings > Python environment > Location of Jython standalone JAR) to run Python BApps. JRuby does
  the same for Ruby. Preconfigured on the AttackBox.
- **API / languages:** extensions talk to Burp via its API (Extensions > APIs tab lists endpoints).
  Write them in Java (native), Python (via Jython), or Ruby (via JRuby). Writing extensions is out
  of scope for this room; PortSwigger has the full dev reference.

## Milestone
This completes the whole **Burp Suite module**: Basics, Repeater, Intruder, Other Modules,
Extensions. Core web-testing workflow now owned: proxy/intercept/edit, Repeater edit-resend loop,
Intruder automation (sniper/battering ram/pitchfork/cluster bomb, credential stuffing, IDOR fuzzing,
macros for CSRF/session), Decoder/Comparer/Sequencer/Organizer, and extending Burp via BApps.
