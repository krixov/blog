---
title: "Incident Response Notes: Containing a Ransomware Intrusion"
date: "2024-12-01"
excerpt: "A narrative runbook with evidence collection, triage commands, and reporting."
featured: "/images/test2.jpg"
tags:
  - incident-response
  - ransomware
  - forensics
  - blue-team
---

## Executive summary

At 03:12 UTC, multiple endpoints began encrypting local files and exfiltrating archives. The initial vector was a compromised VPN credential with no MFA. This post documents the first 24 hours of response as a training template.

## Timeline (first day)

| Time (UTC) | Event |
| --- | --- |
| 03:12 | EDR alerts on mass file rename |
| 03:20 | VPN account disabled |
| 03:35 | Network segmentation enforced |
| 04:10 | Memory image captured on host-01 |
| 06:00 | IOC list published internally |

## Containment actions

1. Disable the compromised VPN account and rotate tokens.
2. Isolate affected hosts at the switch or EDR level.
3. Block known C2 domains and IPs at the firewall.
4. Preserve evidence before reinstalling or wiping.[^1]

## Communication plan

Containment is not only technical. Inform the right people early:

- Incident commander and security lead
- IT operations and endpoint owners
- Legal and compliance teams
- Communications or PR if customer impact is possible

Keep messages short, factual, and time-stamped.

## Evidence collection

Record hashes and timestamps to preserve integrity.

```bash
hostname
whoami
uptime
sha256sum /usr/bin/ssh
ss -tulpn
lsof -nP | head -n 20
```

Capture logs of interest:

```bash
journalctl -u ssh --since "-24 hours" > ssh.log
journalctl --since "-24 hours" > system.log
```

## Forensic collection checklist

- [x] Capture memory image on the most critical host
- [x] Collect system, auth, and EDR logs
- [ ] Export VPN logs and authentication events
- [ ] Pull DNS logs for suspect domains
- [ ] Preserve a disk image for deep analysis

## Quick triage notes

- Look for new admin accounts.
- Search for unsigned binaries in temp directories.
- Verify scheduled tasks and cron entries.

Example log snippet:

```text
Oct 01 03:05:11 host-01 sshd[2178]: Accepted password for svc-vpn from 203.0.113.8 port 58422
Oct 01 03:06:02 host-01 sudo: svc-vpn : TTY=pts/0 ; COMMAND=/bin/bash
```

## Scoping and lateral movement

Search for additional access paths and other affected hosts.

```bash
last -a | head -n 20
find /tmp /var/tmp -type f -mtime -2 2>/dev/null | head -n 20
ps aux --sort=-%mem | head -n 15
```

Check for unexpected SSH keys or new services listening on uncommon ports.

## Indicators of compromise

| Type | Value | Notes |
| --- | --- | --- |
| IP | 203.0.113.8 | VPN login source |
| Hash | e3b0c44298fc1c149afbf4c8996fb924 | Sample payload |
| Domain | cdn-update.example | C2 over HTTPS |

## YARA starter rule

```text
rule suspicious_ransomware
{
    meta:
        description = "example rule for lab use"
    strings:
        $s1 = "encrypting files" nocase
        $s2 = { 55 48 89 e5 41 57 41 56 }
    condition:
        1 of them
}
```

## Recovery and eradication

- Rebuild hosts from clean images.
- Reset all passwords for accounts with admin access.
- Review backup integrity and restore in a clean network segment.
- Run a focused hunt for lateral movement.

## Data exfiltration assessment

Review proxy and firewall logs for large outbound transfers. If you use cloud storage, audit object access logs for unusual download patterns. Document what evidence you have and what you do not.

## Lessons learned

- Enforce MFA on all remote access.
- Reduce the number of local admins.
- Tighten egress filtering to reduce data exfiltration paths.
- Practice the playbook quarterly.

## Post-incident hardening

- Enforce MFA and device posture checks on all remote access.
- Implement least privilege for service accounts.
- Add alerting on abnormal login geography and impossible travel.
- Verify backups with periodic restore drills.

## Report outline

1. Summary and scope
2. Root cause and timeline
3. Impacted assets
4. Actions taken
5. Remaining risks
6. Follow-up tasks

## Footnotes

[^1]: Keep original disk images and logs in a read-only location for legal review.

## References

- [NIST 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK](https://attack.mitre.org/)
