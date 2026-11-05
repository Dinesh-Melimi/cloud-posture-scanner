# Breach lab: how it fits together, and how to talk about it

This is the note I use to explain the breach lab in an interview. It is written
the way I would say it out loud, not as marketing.

## The one-sentence version

I built a lab that replays a full AWS account takeover as log telemetry, catches
every stage with detection-as-code mapped to MITRE ATT&CK, and then contains the
attack automatically with real AWS API calls — and I test it so a normal day
never sets it off.

## Why I built it this way

I did not want to write working exploit code. For a portfolio piece that is both
risky and beside the point: the hard, interesting work in a real SOC is on the
defensive side — writing detections that fire on the real thing and stay quiet
on everything else, and responding fast without breaking the business.

So the "attacker" in this lab is the evidence an attack leaves behind. Each step
emits the CloudTrail events, GuardDuty findings and VPC flow records it would
produce in a real account. That is exactly what a detection engineer works from,
and it is how datasets like Splunk Attack Range and Stratus Red Team are used.

## The attack I modelled

A single exposed web app to full account takeover, because that is the path I
see most often written up in real AWS incidents:

1. The app has a server-side request forgery bug.
2. SSRF reaches the instance metadata service and returns the instance role's
   temporary credentials.
3. Those credentials get used from an IP that is not the instance.
4. The attacker enumerates what the role can do.
5. The role can attach IAM policies, so they grant a deploy user allow-*.
6. With admin, they open a customer-data S3 bucket.
7. They bulk-download it.

## The detections

Five rules, one behaviour each, so each is easy to justify:

- **DET-001** GuardDuty: instance credentials used outside AWS (T1552.005).
- **DET-002** an instance role making calls from a foreign IP (T1078.004) — I
  dedupe this to one alert per principal and source IP so one session is one
  alert, not fifty.
- **DET-003** a burst of IAM read/list calls from one principal (T1087).
- **DET-004** a policy change that grants wildcard admin (T1098) — and this is
  the one I am most careful about: it fires only on an allow-* grant, not on
  every policy edit, because an admin making a scoped change all day is normal.
- **DET-005 / DET-006** GuardDuty anomalous S3 reads, and a large outbound
  transfer from the flow logs (T1537).

## The false-positive test

`make breach-baseline` runs the same rules over a benign day: the instance role
working from inside the VPC, an admin making a *scoped* policy change, two IAM
reads (below the burst threshold), a small download. It has to come back with
zero detections. If I loosen a rule and this starts firing, CI fails. That is
the part that makes the detections trustworthy, so it is the part I lead with.

## The response

When the credential and exfil rules fire, the responder:

- snapshots the instance volumes first, so I do not destroy evidence,
- deactivates the compromised access keys,
- attaches a deny-all policy to the principal instead of deleting it — same
  reason, keep the evidence,
- moves the instance into a security group with no egress.

These run against a `moto`-simulated account in the lab, and the tests assert
the real effect each time: the key is actually Inactive, the deny policy is
actually on the user, the instance actually ends up in an empty group, a
snapshot actually exists. The deployed version (Terraform + Lambda) runs the
exact same functions against a live account from a GuardDuty EventBridge rule.

## What I would say are its limits

- The telemetry is modelled, not captured from a live detonation. The detections
  are written against realistic records, but I would want to validate them
  against real GuardDuty output before trusting them in production.
- The AWS "outside the VPC" check is simplified in the lab; a real deployment
  resolves source IPs against the published AWS ranges.
- The Terraform is hand-reviewed, not yet `plan`-ned in a live account.

Being able to say where it stops is, I think, more convincing than pretending it
is production-grade.
