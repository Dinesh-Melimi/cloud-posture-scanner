# Incident report: cloud account intrusion

- **Generated:** 2026-11-05 22:45 UTC
- **Highest severity:** CRITICAL
- **Detections fired:** 6
- **Containment actions taken:** 4

## What happened

A single exposed web application was used to reach the instance metadata service and steal the app server's role credentials. Those credentials were used from an outside IP to enumerate permissions, grant a deploy user full admin, open the customer-export bucket and begin downloading it. Detection-as-code caught the chain and automated containment cut it off.

## Attack timeline (MITRE ATT&CK)

| Step | Tactic | Technique | What happened |
|---|---|---|---|
| Web app reconnaissance | Reconnaissance | T1595 | An outside host probes the public web app, walking URL parameters that look like they fetch remote content. |
| Instance metadata read via SSRF | Credential Access | T1552.005 | A server-side request forgery in the app makes the instance call its own metadata service and return the app-server role's temporary credentials. GuardDuty records the role credentials being used from outside AWS shortly after. |
| Stolen role used from a new IP | Defense Evasion | T1078.004 | The temporary credentials are now driving API calls from the attacker's IP, not from the instance. |
| Permission enumeration | Discovery | T1087 | The attacker maps what the stolen role can do, listing policies and attached permissions -- a burst of read-only IAM calls in a few seconds. |
| Privilege escalation | Privilege Escalation | T1098 | The role can attach IAM policies, so the attacker grants a deploy user full admin by putting an inline allow-all policy on it. This single call is the turning point of the breach. |
| Lateral movement to data store | Collection | T1530 | With admin rights the attacker turns to the customer-export bucket, reading its policy and listing its contents. |
| Data exfiltration | Exfiltration | T1537 | The attacker bulk-downloads the bucket. GuardDuty flags anomalous S3 reads and the flow logs show a large outbound transfer to the attacker IP. |

## Detections

| Time | Rule | Severity | ATT&CK | Why it fired |
|---|---|---|---|---|
| 14:00:45 | DET-001 Instance credentials used outside AWS | CRITICAL | T1552.005 | GuardDuty flagged an instance role's temporary keys being used from an external IP -- the signature of an SSRF or metadata-service credential theft. |
| 14:01:00 | DET-002 Instance role used from a foreign IP | HIGH | T1078.004 | Role arn:aws:sts::111122223333:assumed-role/app-server-role/i-0labdeadbeef00001 first seen calling GetCallerIdentity from 198.51.100.77, which is not the instance address; all later calls from this session are the same alert. |
| 14:01:10 | DET-003 IAM enumeration burst | MEDIUM | T1087 | arn:aws:sts::111122223333:assumed-role/app-server-role/i-0labdeadbeef00001 made 4 IAM discovery calls in quick succession, consistent with permission mapping. |
| 14:01:35 | DET-004 IAM privilege escalation | CRITICAL | T1098 | arn:aws:sts::111122223333:assumed-role/app-server-role/i-0labdeadbeef00001 called PutUserPolicy on arn:aws:iam::111122223333:user/ci-deploy, granting a wildcard allow-all policy. |
| 14:02:30 | DET-005 Anomalous S3 data access | HIGH | T1537 | GuardDuty saw an unusual volume of object reads from acme-customer-exports by a single principal. |
| 14:02:35 | DET-006 Large outbound transfer | MEDIUM | T1537 | 700 MB left 203.0.113.10 toward 198.51.100.77 -- possible bulk exfiltration. |

## Containment

| Time | Action | Target | Detail |
|---|---|---|---|
| 22:45:46 | snapshot_instance_volumes | i-e535912c31aaf7011 | Created snapshot snap-88d351c3c85f8992f of vol-ec7c174f0936f91fb. |
| 22:45:46 | revoke_access_keys | ci-deploy | Deactivated access key AKIARZPUZDIKMQYECU6L. |
| 22:45:46 | quarantine_principal | ci-deploy | Attached deny-all inline policy; the user can no longer act. |
| 22:45:47 | isolate_instance | i-e535912c31aaf7011 | Replaced security groups with no-egress group sg-4c4cc34f426242181. |

## Recommended follow-up

- Patch the SSRF in the web app and require IMDSv2 (hop limit 1) on every instance so the metadata service cannot be reached through a proxied request.
- Scope the app-server role down to only the APIs it needs.
- Review the quarantined user's recent activity before re-enabling it.
- Confirm the forensic snapshot is retained with the case.
