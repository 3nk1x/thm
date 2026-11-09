# Summit (TryHackMe)

- **Path/module:** Cyber Defence Frameworks / Summit. Purple-team detection engineering challenge based on the Pyramid of Pain.
- **Date:** 2026-10-26.
- **Status:** Answers documented; validate against the active room instance if the challenge data changes.
- **Objective:** Detect and prevent six progressively modified malware samples, forcing the simulated adversary higher up the Pyramid of Pain.

## Flags

| Sample | Detection level | Flag |
|---|---|---|
| `sample1.exe` | File hash | `THM{…}` |
| `sample2.exe` | IP address | `THM{…}` |
| `sample3.exe` | Domain name | `THM{…}` |
| `sample4.exe` | Network behavior / Sigma rule | `THM{…}` |
| `sample5.exe` | Repeated network pattern / Sigma rule | `THM{…}` |
| Final Sphinx message | File behavior / Sigma rule | `THM{…}` |

## Walkthrough

### 1. Sample 1: hash detection

Open the first Sphinx email and select `sample1.exe`. Submit it to the Malware Sandbox and copy one of its file hashes, preferably SHA256. Open **Manage Hashes**, select the matching hash type, paste the value, and submit it.

The hash uniquely identifies the current binary, so the sample is blocked and Sphinx sends the first flag together with `sample2.exe`.

### 2. Sample 2: IP blocking

Submit `sample2.exe` to the sandbox. Its hash has changed, so hash blocking is no longer sufficient. Review the network activity and identify the outbound C2 address, then open **Firewall Rule Manager** and create an outbound (**Egress**) deny rule for that destination IP.

This blocks the sample and produces the second flag.

### 3. Sample 3: domain blocking

Analyze `sample3.exe`. The adversary has changed the IP address, but the malware still communicates with a recognizable domain. Add that domain to **DNS Rule Manager** as a deny rule. This detects the infrastructure at a higher Pyramid of Pain level than a single IP address.

### 4. Sample 4: network-connection Sigma rule

Analyze `sample4.exe` and inspect its network behavior. Rather than blocking one changing address, use **Sigma Rule Builder** and select the Sysmon network-connection event type. Build a rule around the suspicious connection behavior, leaving the remote host and port broad enough to catch infrastructure changes.

Submit the rule and wait for the success notification and fourth flag.

### 5. Sample 5: recurring network pattern

Analyze `sample5.exe`. Look for the distinctive repeated outbound traffic pattern, including its regular timing and small request size. Create another Sigma rule for the recurring Sysmon network behavior instead of relying on a fixed IP, domain, or port.

Successful detection produces the fifth flag.

### 6. Final sample: file behavior

The final Sphinx email includes command logs for the last sample. The malware gathers system and network information and writes the results to a file in the temporary directory, such as `exfiltr8.log`.

Use Sigma Rule Builder with a Sysmon file-creation/modification event and match the suspicious output-file behavior. Once the rule prevents the final sample from completing, Sphinx sends the final flag.

## Lessons learned

- Hashes are precise but trivial for an attacker to change.
- IP addresses and domains raise the attacker’s cost but can still be rotated.
- Behavioral rules are more resilient because they identify what the malware does rather than only where it connects.
- The Pyramid of Pain progression is: hash values -> IP addresses -> domains -> network behavior -> recurring behavior -> attacker tools and operational behavior.
