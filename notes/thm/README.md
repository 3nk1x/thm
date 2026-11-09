# TryHackMe — Room Write-Ups

Study notes and walkthroughs for TryHackMe rooms, one Markdown file per room: the vulnerability, the method, reproducible steps, and lessons learned.

> **These are learning notes, not answer keys.** Flags (`THM{…}`), target IP addresses (`<ip>`), password hashes/keys (`<redacted-hash>`), discovered credentials (`<redacted-pw>`), and room answers (`*(find it yourself)*`) are deliberately redacted. The point is to teach the technique so you can solve the room yourself.


## Active Directory

- [Active directory basics](active-directory-basics.md)
- [Ad authenticated enumeration](ad-authenticated-enumeration.md)
- [Ad badsuccessor](ad-badsuccessor.md)
- [Ad basic enumeration](ad-basic-enumeration.md)
- [Dead drop](dead-drop.md)
- [Dead endpoint](dead-endpoint.md)
- [Intro to ad authentication](intro-to-ad-authentication.md)
- [Intro to ad breaching](intro-to-ad-breaching.md)
- [Intro to ad lateral movement](intro-to-ad-lateral-movement.md)
- [Intro to credential harvesting](intro-to-credential-harvesting.md)
- [Metasploit payload generation](metasploit-payload-generation.md)
- [Shell payload generation and delivery](shell-payload-generation-and-delivery.md)

## Burp Suite

- [Burp suite basics](burp-suite-basics.md)
- [Burp suite extensions](burp-suite-extensions.md)
- [Burp suite intruder](burp-suite-intruder.md)
- [Burp suite other modules](burp-suite-other-modules.md)
- [Burp suite repeater](burp-suite-repeater.md)

## Metasploit

- [Metasploit post exploitation](metasploit-post-exploitation.md)
- [Metasploit scanning and exploitation](metasploit-scanning-and-exploitation.md)
- [Metasploit the basics](metasploit-the-basics.md)

## Web & API security

- [Advanced sql injection](advanced-sql-injection.md)
- [Api pentesting](api-pentesting.md)
- [Broken authentication](broken-authentication.md)
- [Command injection](command-injection.md)
- [Content discovery](content-discovery.md)
- [Csrf introduction](csrf-introduction.md)
- [File inclusion](file-inclusion.md)
- [Idor](idor.md)
- [Insecure deserialisation](insecure-deserialisation.md)
- [Jwt security](jwt-security.md)
- [Ldap injection](ldap-injection.md)
- [Modern web stacks](modern-web-stacks.md)
- [Multi factor authentication](multi-factor-authentication.md)
- [Nosql injection](nosql-injection.md)
- [Oauth vulnerabilities](oauth-vulnerabilities.md)
- [Orm injection](orm-injection.md)
- [Owasp 2025 application design flaws](owasp-2025-application-design-flaws.md)
- [Owasp 2025 iaaa failures](owasp-2025-iaaa-failures.md)
- [Owasp 2025 insecure data handling](owasp-2025-insecure-data-handling.md)
- [Server side template injection](server-side-template-injection.md)
- [Session management](session-management.md)
- [Sql injection introduction](sql-injection-introduction.md)
- [Ssrf introduction](ssrf-introduction.md)
- [Walking an application](walking-an-application.md)
- [Web server attacks 1](web-server-attacks-1.md)
- [Xss introduction](xss-introduction.md)
- [Xxe injection](xxe-injection.md)

## Privilege escalation

- [Host server configuration reviews](host-server-configuration-reviews.md)
- [Jump](jump.md)
- [Linux privilege escalation automation](linux-privilege-escalation-automation.md)
- [Linux privilege escalation basics](linux-privilege-escalation-basics.md)
- [Linux privilege escalation enumeration](linux-privilege-escalation-enumeration.md)
- [Windows jump](windows-jump.md)
- [Windows privilege escalation](windows-privilege-escalation.md)

## Recon, scanning & wordlists

- [Basic vulnerability identification techniques](basic-vulnerability-identification-techniques.md)
- [Enumeration brute force](enumeration-brute-force.md)
- [Introduction to wordlists](introduction-to-wordlists.md)
- [Net sec challenge](net-sec-challenge.md)
- [Network recon and protocols](network-recon-and-protocols.md)
- [Understanding vulnerability databases](understanding-vulnerability-databases.md)
- [Vulnerability scanning tools](vulnerability-scanning-tools.md)

## Password attacks

- [Checkmate](checkmate.md)
- [Hydra](hydra.md)
- [Password cracking](password-cracking.md)

## Shells, payloads & frameworks

- [Exploitation and weaponisation](exploitation-and-weaponisation.md)
- [Pentest frameworks and kill chain](pentest-frameworks-and-kill-chain.md)
- [Python scripting basics](python-scripting-basics.md)
- [Shells and listeners fundamentals](shells-and-listeners-fundamentals.md)

## AI / LLM security

- [Agentic fundamentals](agentic-fundamentals.md)
- [Agentic security monitoring](agentic-security-monitoring.md)
- [Agentic threat modelling](agentic-threat-modelling.md)
- [Agentory](agentory.md)
- [Cypheron nightmare](cypheron-nightmare.md)
- [Cypheron trojaned model](cypheron-trojaned-model.md)
- [Frankesqwen](frankesqwen.md)
- [Llm pentesting](llm-pentesting.md)
- [The guestbook](the-guestbook.md)
- [The thm bounty hunt](the-thm-bounty-hunt.md)

## Blue team, DFIR & phishing

- [Boogeyman 2](boogeyman-2.md)
- [Boogeyman 3](boogeyman-3.md)
- [Deadmen tell no logs](deadmen-tell-no-logs.md)
- [Handbook for the recently compromised](handbook-for-the-recently-compromised.md)
- [Phishing basics](phishing-basics.md)
- [Silent monitor](silent-monitor.md)
- [Snapped phishing line](snapped-phishing-line.md)
- [Strange and unusual activity](strange-and-unusual-activity.md)
- [The blue team perspective](the-blue-team-perspective.md)
- [The waiting room](the-waiting-room.md)

## Cloud, DevSecOps, mobile & wireless

- [Cloud security fundamentals](cloud-security-fundamentals.md)
- [Devsecops basics](devsecops-basics.md)
- [Mobile application security](mobile-application-security.md)
- [Wireless security](wireless-security.md)

## Methodology & reporting

- [Planning and scoping](planning-and-scoping.md)
- [Re testing](re-testing.md)
- [Threat modeling for pentesters](threat-modeling-for-pentesters.md)
- [Writing pentest reports](writing-pentest-reports.md)

## Challenge & practice boxes

- [Beach bar](beach-bar.md)
- [Critical condition](critical-condition.md)
- [Day o](day-o.md)
- [Directory](directory.md)
- [Domino](domino.md)
- [Forward](forward.md)
- [Fragnesia CVE 2026 46300](fragnesia-cve-2026-46300.md)
- [Guided pentest infrastructure](guided-pentest-infrastructure.md)
- [Hammer](hammer.md)
- [Injectics](injectics.md)
- [Interceptor](interceptor.md)
- [Jackpot](jackpot.md)
- [N8n CVE 2025 68613](n8n-cve-2025-68613.md)
- [Noscope finding rce](noscope-finding-rce.md)
- [Operation coldstart](operation-coldstart.md)
- [Operation promotion](operation-promotion.md)
- [Phantom fob](phantom-fob.md)
- [Proxy](proxy.md)
- [Ps eclipse](ps-eclipse.md)
- [Quiet as the grave](quiet-as-the-grave.md)
- [Recruit](recruit.md)
- [Repossessed](repossessed.md)
- [Rubber stamp](rubber-stamp.md)
- [Scheme catcher](scheme-catcher.md)
- [Summit](summit.md)
- [Support](support.md)
- [Zero tolerance](zero-tolerance.md)

---

_123 rooms._
