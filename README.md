<div align="center">

# 🛡️ Active Directory Attack & Defense Lab
### Kerberoasting → Full Domain Compromise → SIEM Detection

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=3500&pause=800&color=2F81F7&center=true&vCenter=true&width=720&lines=Unauthenticated+Recon+to+Domain+Admin%2C+then+Detect+It;Kerberoasting+%7C+AS-REP+%7C+DCSync+%7C+Pass-the-Hash;9-Stage+Attack+Chain+%2B+SIEM+Detections+mapped+to+MITRE" alt="typing summary" />

<p>
  <img src="https://img.shields.io/badge/Type-Purple%20Team%20(Red%20%2B%20Blue)-4B0082?style=for-the-badge" alt="type" />
  <img src="https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-2F81F7?style=for-the-badge" alt="mitre" />
  <a href="AD-Lab-Report.pdf"><img src="https://img.shields.io/badge/Offensive%20Report-PDF-0A2A66?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" alt="offensive report" /></a>
</p>
<p>
  <img src="https://img.shields.io/badge/Windows%20Server%202022-0078D6?style=flat-square&logo=windows&logoColor=white" alt="windows server" />
  <img src="https://img.shields.io/badge/Ubuntu%2026.04%20ARM64-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="ubuntu" />
  <img src="https://img.shields.io/badge/Impacket-2F81F7?style=flat-square" alt="impacket" />
  <img src="https://img.shields.io/badge/Hashcat-2F81F7?style=flat-square" alt="hashcat" />
  <img src="https://img.shields.io/badge/BloodHound%20CE-2F81F7?style=flat-square" alt="bloodhound" />
  <img src="https://img.shields.io/badge/Nmap-2F81F7?style=flat-square" alt="nmap" />
</p>
<p>
  <img src="https://img.shields.io/badge/Blue%20Team-Microsoft%20Sentinel%20%2B%20Defender%20XDR-0078D6?style=flat-square&logo=microsoftazure&logoColor=white" alt="sentinel defender" />
  <img src="https://img.shields.io/badge/Part%20II%20Detection-%F0%9F%9A%A7%20In%20Progress-orange?style=flat-square" alt="part 2 in progress" />
</p>

</div>

A hands-on **purple-team** Active Directory lab. **Part I (complete)** walks a full offensive attack chain end to end, from unauthenticated network recon on the LAN to Domain Administrator access on a live Windows Server domain controller. **Part II (in progress)** instruments that same domain controller, ships its telemetry into a SIEM, and detects the entire attack chain, turning every offensive step into a validated detection, a triaged case, and a response playbook.

The lab is built across two machines and two CPU architectures, an ARM64 Linux attacker box on Apple Silicon and an x86 Windows Server domain controller, bridged onto the same network.

> ### 🚧 Project Status
> - ✅ **Part I (Offensive chain):** complete (9 stages, full report in `AD-Lab-Report.pdf`)
> - 🚧 **Part II (Blue-team detection & response):** in progress. Instrumenting the DC, building Microsoft Sentinel analytics rules (with Defender XDR) for each attack stage, and producing a detection & response report. Progress tracked in the [Part II section](#part-ii--blue-team-detection--response-) below.

## Lab Architecture

| Component | Details |
|---|---|
| Attacker host | Apple Mac Mini M4, 32GB RAM, UTM virtualization |
| Attacker VM | Ubuntu Server 26.04 ARM64 running impacket, hashcat, BloodHound CE (`192.168.1.126`) |
| Domain Controller | Windows Server 2022 (VirtualBox on an x86 laptop), `adlab.lan`, `192.168.1.240` |
| Network | Bridged (192.168.1.0/24) |
| **SIEM (Part II)** 🚧 | **Microsoft Sentinel + Microsoft Defender XDR. DC01 onboarded via Azure Monitor Agent + Sysmon (the Microsoft-stack counterpart to the Elastic [soc-siem-lab](https://github.com/jsmith-sec/soc-siem-lab))** |

## What Was Built

- Windows Server 2022 domain controller, promoted to a new forest (`adlab.lan`) with a static IP and self-hosted DNS
- Deliberately vulnerable domain objects: a Kerberoastable service account (SPN + weak password), an AS-REP roastable user (Kerberos pre-authentication disabled), and an over-privileged service account
- Ubuntu ARM64 attacker box tooled with impacket, hashcat, and BloodHound Community Edition
- A cross-architecture, cross-machine bridged network (ARM64 attacker ↔ x86 domain controller) so the lab mirrors a real internal-network engagement
- 🚧 **(Part II)** DC instrumented with advanced audit policy + Sysmon, forwarding the Security and Sysmon channels to Microsoft Sentinel via the Azure Monitor Agent, and onboarded to Microsoft Defender XDR for endpoint telemetry

## Attack Chain

| Stage | Technique | Tooling | MITRE ATT&CK |
|---|---|---|---|
| 1 | Network service discovery | Nmap | T1046 |
| 2 | Kerberoasting | impacket `GetUserSPNs.py` + hashcat (mode 13100) | T1558.003 |
| 3 | AS-REP Roasting | impacket `GetNPUsers.py` + hashcat (mode 18200) | T1558.004 |
| 4 | Offline password cracking | hashcat + rockyou | T1110.002 |
| 5 | Valid-account privilege abuse | Domain Admin service account | T1078.002 |
| 6 | Lateral movement / remote execution | impacket `wmiexec.py` | T1047 |
| 7 | Credential dumping (DCSync) | impacket `secretsdump.py` | T1003.006 |
| 8 | Pass-the-Hash | impacket `wmiexec.py -hashes` | T1550.002 |
| 9 | Attack-path analysis | BloodHound CE | T1069.002 |

---

## Walkthrough

### 1. Reconnaissance

Confirmed reachability to the domain controller across the bridged network, then scanned for the hallmark Active Directory service ports, Kerberos (88), RPC (135), LDAP (389/636), and SMB (445), all of which identify the host as a domain controller.

<img src="images/01-connectivity-check.png" width="600" alt="Connectivity check">

*The attacker box reaches the domain controller, three ICMP replies, with TTL 128 confirming a Windows host.*

<img src="images/02-port-scan.png" width="600" alt="Port scan, AD services exposed">

*An `nmap -Pn` scan shows Kerberos (88), RPC (135), LDAP/LDAPS (389/636), and SMB (445) all open, the signature of a domain controller.*

### 2. Lab Environment

The target domain was populated with standard and deliberately vulnerable accounts to create realistic attack paths.

<img src="images/03-lab-accounts.png" width="600" alt="Lab accounts created on the DC">

*Creating the domain's standard and intentionally-vulnerable accounts on the DC via PowerShell.*

### 3. Kerberoasting

As an ordinary domain user, requested the Kerberos service ticket for the `svc_sql` account (which exposes a Service Principal Name), then cracked the ticket offline to recover its plaintext password.

<img src="images/04-kerberoast-extract.png" width="600" alt="Kerberoast, extract svc_sql ticket">

*`GetUserSPNs.py` requests the `svc_sql` service ticket, exposing its `$krb5tgs$` hash.*

<img src="images/05-kerberoast-crack.png" width="600" alt="Kerberoast, crack svc_sql">

*hashcat cracks the ticket offline, the `svc_sql` password is recovered as `Password1`.*

### 4. AS-REP Roasting

Targeted an account with Kerberos pre-authentication disabled, which allows a hash to be requested with **no credentials at all**, only a valid username, then cracked it offline.

<img src="images/06-asrep-prepped.png" width="600" alt="AS-REP target prepared (pre-auth disabled)">

*The `asrep` account confirmed with Kerberos pre-authentication disabled (`DoesNotRequirePreAuth = True`).*

<img src="images/07-asrep-extract.png" width="600" alt="AS-REP roast, extract ticket">

*`GetNPUsers.py` retrieves the `asrep` AS-REP hash, no target credentials required, only a username.*

<img src="images/08-asrep-crack.png" width="600" alt="AS-REP roast, crack">

*hashcat cracks the AS-REP hash offline, password recovered as `Password1`.*

> **Note: the recovered password is intentionally the same as the Kerberoast target.** Both deliberately-vulnerable accounts (`svc_sql` and `asrep`) were assigned the weak password `Password1` to demonstrate password reuse. Because NTLM is unsalted, the two accounts share the *identical* NT hash (`64f12cddaa88057e06a81b54e73b949b`), visible in the DCSync dump below. This is a deliberate teaching point, not a duplicated result.

### 5. Privilege Abuse & Lateral Movement

The cracked `svc_sql` account was a member of **Domain Admins**, a common real-world misconfiguration of over-privileged service accounts. Those credentials were used to gain remote code execution on the domain controller.

> Note: both `psexec` and the "fileless" `wmiexec` techniques were initially caught by Microsoft Defender on the DC, a useful blue-team observation. Defender was then disabled on the lab DC to study the attack mechanics.

<img src="images/09-svcsql-domain-admin.png" width="600" alt="Service account added to Domain Admins">

*`svc_sql` confirmed as a member of Domain Admins, the over-privileged service account misconfiguration.*

<img src="images/10-wmiexec-shell.png" width="600" alt="Remote shell on DC via wmiexec">

*`wmiexec.py` yields a remote shell on DC01 as `adlab\svc_sql`.*

### 6. Credential Dumping (DCSync)

With Domain Admin-level access, performed a DCSync attack to replicate the domain's password database (NTDS.dit) directly from the DC, dumping every account's NTLM hash, including `krbtgt` (the key to forging Golden Tickets) and the built-in Administrator.

<img src="images/11-dcsync-dump.png" width="600" alt="DCSync, full domain hash dump">

*`secretsdump.py` performs a DCSync, replicating every account's NTLM hash from the DC, including `krbtgt` and the built-in Administrator.*

### 7. Pass-the-Hash

Authenticated as the domain Administrator using only the stolen NTLM hash, no password, no cracking, proving that a captured hash alone is enough to fully own the domain.

<img src="images/12-pass-the-hash.png" width="600" alt="Pass-the-Hash as Administrator">

*`wmiexec.py -hashes` authenticates as `adlab\administrator` using only the stolen NTLM hash, no password, no cracking.*

### 8. Attack-Path Analysis with BloodHound

Ingested the domain into BloodHound Community Edition to visualize the privilege relationships that made the compromise possible, the direct path from the service account to Domain Admins, every account holding Domain Admin rights, and every principal capable of the DCSync attack.

<img src="images/13-bloodhound-attack-path.png" width="650" alt="BloodHound, attack path svc_sql to Domain Admins">

*BloodHound Pathfinding renders the direct edge: `SVC_SQL` --MemberOf--> `DOMAIN ADMINS`.*

<img src="images/14-bloodhound-domain-admins.png" width="650" alt="BloodHound, all Domain Admins">

*All three accounts holding Domain Admin rights, including the service account that shouldn't.*

<img src="images/15-bloodhound-dcsync.png" width="650" alt="BloodHound, principals with DCSync privileges">

*Every principal able to perform DCSync against the domain, the privilege abused in step 6.*

---

## Results

- **Full domain compromise** achieved starting from an unauthenticated position on the local network
- **Two Kerberos roasting techniques** (Kerberoasting + AS-REP Roasting) both cracked in under 10 seconds against the rockyou wordlist
- **Complete NTDS.dit dump** via DCSync, exposing every domain hash including `krbtgt`
- **Domain Administrator access** obtained via Pass-the-Hash with no password cracking
- **Detection insight:** both remote-execution techniques were caught by Microsoft Defender before evasion, demonstrating the defensive value of endpoint monitoring

## Key Findings & Defensive Takeaways

| Finding | Risk | Remediation |
|---|---|---|
| Over-privileged service account (`svc_sql` in Domain Admins) | A single cracked service password = full domain compromise | Remove service accounts from privileged groups; apply tiered administration |
| Weak / reused passwords | `svc_sql` and `asrep` shared an identical NT hash, and password reuse is trivially exploitable because NTLM is unsalted | Enforce long, unique passwords; use Group Managed Service Accounts (gMSA) |
| Kerberos pre-authentication disabled | Enables credential-free AS-REP Roasting | Require pre-authentication on all accounts |
| SPNs on weak-password accounts | Enables Kerberoasting | Strong passwords on all SPN-bearing accounts; monitor for anomalous TGS requests |

## Detection Opportunities

Every technique in this chain leaves evidence in Windows Security event logs. During the lab, Microsoft Defender independently flagged both the `psexec` and `wmiexec` execution attempts before evasion, a live confirmation that these attacks are observable. A defender monitoring the domain controller could detect this chain at multiple points:

| Attack | Primary detection signal |
|---|---|
| Kerberoasting | Event ID **4769**, a TGS service-ticket request, especially using RC4 encryption (`0x17`) against a user account with an SPN |
| AS-REP Roasting | Event ID **4768**, an AS-REQ for an account flagged "does not require pre-authentication" |
| Lateral movement (wmiexec) | Event ID **4624** (NTLM network logon, type 3) paired with **4688** process creation for the WMI-spawned `cmd.exe`, plus the Defender alert on the execution attempt |
| DCSync | Event ID **4662**, directory-replication access (`DS-Replication-Get-Changes`) requested by a principal that is not a domain controller |
| Pass-the-Hash | Event ID **4624** (logon type 3, NTLM) and **4672** (special privileges) for the Administrator account from an unexpected source host |

The single highest-value defensive control across this whole chain is protecting and monitoring Tier Zero assets. A service account should never hold Domain Admin, and DCSync-equivalent rights (`4662`) from a non-DC should always alarm.

> **→ Part II operationalizes this table.** The detection signals above are being built into live Microsoft Sentinel analytics rules (with Defender XDR advanced hunting), triaged as cases, and wrapped in a response playbook. See below.

---

## Part II — Blue Team: Detection & Response 🚧

> **Status: In progress.** This section turns the offensive chain into a defensive one. The DC is instrumented and its telemetry forwarded to **Microsoft Sentinel**, with endpoint detection from **Microsoft Defender XDR**. Each attack stage becomes a validated analytics rule, a triaged incident, and a response action. This is the Microsoft-stack counterpart to the Elastic-based [soc-siem-lab](https://github.com/jsmith-sec/soc-siem-lab), and it maps directly onto enterprise SOC toolchains built on Sentinel + Defender.

### Approach

The attack chain from Part I is **replayed against a fully instrumented domain controller**, and each stage is detected end to end. Because the attacks are self-generated, every detection is validated against known ground truth, an attack-to-detection timeline with no ambiguity about what fired and why.

### Detection Rules (planned)

Each offensive stage maps to a **Microsoft Sentinel analytics rule** (KQL over the `SecurityEvent` table via the Azure Monitor Agent), with **Defender XDR advanced hunting** where the endpoint signal is richer. Severity uses Sentinel's native scale:

| # | Detection rule | Signal (source) | MITRE | Severity |
|---|---|---|---|---|
| 1 | Kerberoasting, RC4 TGS request | `SecurityEvent` 4769, `TicketEncryptionType 0x17`, SPN account | T1558.003 | 🚧 High |
| 2 | AS-REP Roasting, pre-auth-disabled AS-REQ | `SecurityEvent` 4768, `PreAuthType 0`, RC4 | T1558.004 | 🚧 Medium |
| 3 | DCSync from non-DC principal | `SecurityEvent` 4662, `DS-Replication-Get-Changes` GUID, non-`$` account | T1003.006 | 🚧 High |
| 4 | WMI lateral movement | Defender XDR `DeviceProcessEvents`, `WmiPrvSE.exe` → `cmd.exe`/`powershell.exe` (or 4688) | T1047 | 🚧 High |
| 5 | Pass-the-Hash, anomalous privileged NTLM logon | `SecurityEvent` 4624 type 3 NTLM + 4672, Administrator from unexpected host | T1550.002 | 🚧 High |

### Planned Deliverables

- [ ] `detections/`: one Sentinel analytics rule (KQL, exported as ARM/YAML) per detection above, plus Defender XDR advanced-hunting queries, each with MITRE + severity
- [ ] `detections/audit-policy.md`: the advanced audit policy + Sysmon config enabled on the DC
- [ ] `cases/`: a triaged case note per fired alert (legitimacy, severity, business impact, IOCs, escalation)
- [ ] `playbooks/kerberoasting-response.md`: a full SOC response playbook (trigger → validation → containment → escalation)
- [ ] `detections/tuning-notes.md`: false-positive tuning story (baseline vs tuned volume)
- [ ] `hunt-queries/`: proactive threat-hunting queries (mass-SPN requests, non-DC replication)
- [ ] `AD-Lab-BlueTeam-Report.pdf`: full detection & response writeup with attack-to-detection timeline

---

## Full Report

See [AD-Lab-Report.pdf](AD-Lab-Report.pdf) for the complete **offensive** write-up, including the executive summary, full attack narrative with commands and evidence, findings with severity and remediation, MITRE ATT&CK mapping, and detection guidance. The **blue-team** report (`AD-Lab-BlueTeam-Report.pdf`) is in progress and will cover the detection engineering, triaged cases, response playbook, tuning notes, and incident timeline.

## Using Claude as a Tool

I used Claude (Anthropic) as a tool throughout this lab, the same way I use it across the series. It helped me walk through each stage, deepen my understanding of the techniques as I ran them, and document what I did along the way. I directed the work, made the operational decisions, and ran every domain-controller action myself, verifying each command and result independently.

## Tools & Assistance

- Windows Server 2022 (Active Directory Domain Services)
- Ubuntu Server 26.04 ARM64
- UTM (Apple Silicon virtualization) · Oracle VirtualBox
- impacket 0.13.1 (`GetUserSPNs`, `GetNPUsers`, `wmiexec`, `secretsdump`)
- hashcat · John the Ripper · rockyou wordlist
- BloodHound Community Edition
- Nmap
- 🚧 **(Part II)** Microsoft Sentinel · Microsoft Defender XDR · Azure Monitor Agent · Sysmon · Windows advanced audit policy
- AI assistance provided by [Claude](https://claude.ai) (Anthropic) during lab development and documentation.

## Other Labs in This Series

| Lab | Topic | Repo |
|---|---|---|
| Lab 1 | SOC/SIEM Detection | [soc-home-lab](https://github.com/jsmith-sec/soc-home-lab) |
| Lab 2 | Incident Response Simulation | [incident-response-lab](https://github.com/jsmith-sec/incident-response-lab) |
| Lab 3 | Web Application Attack | [web-app-attack-lab](https://github.com/jsmith-sec/web-app-attack-lab) |
| Lab 4 | Vulnerability Assessment | [vulnerability-assessment-lab](https://github.com/jsmith-sec/vulnerability-assessment-lab) |
| Lab 5 | Malware Analysis | [malware-analysis-lab](https://github.com/jsmith-sec/malware-analysis-lab) |
| Lab 6 | Phishing Analysis | [phishing-analysis-lab](https://github.com/jsmith-sec/phishing-analysis-lab) |
| Lab 7 | Active Directory Attack & Defense | This repo |
