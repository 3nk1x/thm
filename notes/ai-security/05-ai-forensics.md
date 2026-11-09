# Room 5: AI Forensics
Path: AI Security → AI Fundamentals | Completed: 2026-10-03

## One-line memory version
> AI finds the clues fast, but a human has to check them and stand behind them in court.

## DFIR basics
- **DFIR** = Digital Forensics (crime-scene investigators: what happened, how, who) + Incident Response (firefighters: stop it now).
- **Artefacts** = digital clues (logs, files, timestamps). **Timeline** = events in order.
- **Chain of custody** = record of who handled evidence and when. **Integrity** = prove it wasn't changed (hashes).

## What AI does for detectives
- **Data processing**: reads mountains of evidence fast.
- **Anomaly detection**: learns "normal", flags the odd one out (turns the haystack into a handful of hay). E.g. **impossible logins** (London + Tokyo at once).
- **Scalability**: covers cloud, laptops and servers without more staff.
- Tools: Splunk UEBA, Elastic ML, Microsoft Defender, CrowdStrike Charlotte AI, Timesketch, Velociraptor.

## 4 detective jobs
| Area | AI tech | Plain words |
|---|---|---|
| Image/video | **CNN** (Convolutional Neural Network) + **ELA** | Picture expert; ELA highlights edited patches |
| Deepfakes | **GANs** | Forger vs detective AI. Arms race, used by both sides |
| Communications | BERT/RoBERTa, **sentiment analysis** | Reads emails/chats, spots phishing (99%), reads mood |
| Timelines | Correlates **time-sequenced** data | Merges logs into one story |
| Malware | **Static** (inspect without running) vs **dynamic** (run in sandbox, watch) | Parcel from outside vs open in bomb-disposal room |

## Judging an AI: fishing for poisonous fish (99 good, 1 bad)
- **Accuracy**: overall right %. Misleading. "All good" = 99% but misses the bad one.
- **Precision**: "Were my alarms real?" (few false positives)
- **Recall**: "Did I catch them all?" (few misses)
- Never trust one number. **F1** = precision + recall combined.

## AI's limits
- **Non-determinism / probabilistic**: different answers each run. Courts need repeatable results.
- **GIGO** (Garbage In, Garbage Out): bad data gives confidently wrong answers, which could blame the wrong person.
- AI is a power tool, **not a replacement** for the analyst.

## Legal & ethical: why AI evidence gets thrown out
| Problem | Example | Fix |
|---|---|---|
| **Explainability** (black box) | AI flagged emails, nobody could explain why → excluded | Human expert validates and explains |
| **Bias** | **Facial recognition** → 7+ wrongful arrests, mostly Black people | Test for bias, diverse data |
| **Chain of custody** | AI summarised a phone, steps not logged → challenged | Log every AI step, on-prem tools |
| **Privacy** | Cloud AI exposes evidence, breaks GDPR | Offline tools, **federated learning** |
- **Daubert test** = US rule: is the expert's method scientific and reliable?
- "With great power comes great responsibility."

## Practical: The Digital Trail (RobbCo case)
Attack chain:
1. 📧 **Phishing** email to j.morgan (`/home/j.morgan/Mail/inbox/email_invoice.eml`)
2. 📄 `invoice_Q1_2075.ods` with a **macro** → harvested history, SSH keys, /etc/passwd → `/tmp/invoice_dump.txt` → exfiltrated
3. 🔑 Attacker logs in as j.morgan at night
4. 🐚 `/tmp/.syncd` (dropper) + `/tmp/.x` (**reverse shell** to 10.0.0.66:4444)
5. 👑 `sudo nano /home/r.house/.ssh/authorized_keys` → planted SSH key = privilege escalation by **abusing legit permissions**
6. 🎭 `/usr/local/bin/sysmon` (reverse shell disguised as a tool) + fake `boot_monitor.log` = **persistence through deception**
7. 📦 Source code zipped + base64'd → `/dev/shm/.core_dump_2025.tgz.enc` (hidden in shared memory)
- The AI also flagged the **real source code** = **false positive** → human validation always needed.

## Linux commands learned
| Command | Does |
|---|---|
| `ls -la` | List everything, including hidden (`.name`) files |
| `ls -laR` | Same, inside every subfolder |
| `cat file` | Show a file's contents |
| `grep -ri "word" folder` | Search all files for a word |
| `cmd \| grep word` | Pipe: filter one command's output |
| `sudo` | Run as admin |
| `source .../activate` | Enter a Python virtual environment |
| **Tab** key | Auto-complete paths |
- `.eml` = saved email file. `/dev/shm` = shared memory (stealthy hiding spot). `/tmp` = temp folder (common for malware).
