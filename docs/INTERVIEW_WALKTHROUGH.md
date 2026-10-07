# Interview Walkthrough

Plain-English explanation of every part of the project, followed by questions an
interviewer is likely to ask and honest answers.

## The 30-second pitch

"I built a small Python CLI that connects to an AWS account with read-only
permissions, runs 12 security checks mapped to the CIS AWS Foundations Benchmark,
and produces JSON, Markdown, and HTML reports with remediation steps. Each check is
a plugin, every check is unit-tested against a mocked AWS with moto, and CI runs
lint, a static security scan, and tests on each push."

## Component by component

### `scanner/models.py`
Defines the data shapes. `Severity` (CRITICAL to LOW) and `Status` (PASS / FAIL /
ERROR) are enums so typos are impossible. A `Finding` is one result: which check,
which resource, pass or fail, why, and how to fix it. `ScanResult` holds all
findings plus account info, and `summary()` computes counts per severity and an
overall pass percentage.

### `scanner/checks/base.py`
The plugin system. `BaseCheck` is an abstract class: every check must provide an
ID, title, CIS reference, severity, remediation text, and a `run()` method. The
`@register` decorator puts the class into a dictionary called `REGISTRY` the moment
the module is imported, and refuses duplicate IDs. The engine never needs a
hand-maintained list of checks. `regional = True` means "run this once per region".
Helpers `passed()` and `failed()` build findings so each check stays short.

### `scanner/checks/iam.py`
- **IAM-001 / IAM-002**: `GetAccountSummary` returns flags for root MFA and root
  access keys. One API call answers both.
- **IAM-003**: reads the password policy. No policy at all is a failure; otherwise
  checks minimum length 14 and reuse prevention 24.
- **IAM-004**: uses the IAM *credential report*, a CSV AWS generates with last-used
  dates for every password and access key. If a credential is active and its
  last use (or creation date if never used) is over 90 days old, it fails. The
  current time is injectable so tests can "jump ahead" 120 days.
- **IAM-005**: lists users and their directly attached policies; flags any user with
  `AdministratorAccess`. CIS wants permissions through groups/roles, not users.

### `scanner/checks/s3.py`
- **S3-001**: for each bucket, all four Block Public Access flags must be true. A
  missing configuration raises a specific error code, which is treated as a fail;
  any other error is re-raised so the engine reports it as ERROR.
- **S3-002**: checks a default encryption rule exists.

### `scanner/checks/logging.py`
- **LOG-001**: passes only if there is a trail that is multi-region **and** currently
  logging **and** has log file validation (tamper-evident digest files). Shadow
  trails are included so a multi-region trail homed in another region still counts.
- **LOG-002**: GuardDuty must have an enabled detector in each scanned region. This
  is labeled "supplemental" because it is an AWS Foundational Security Best
  Practices control, not a CIS one.

### `scanner/checks/network.py`
- **NET-001**: walks every security group rule. A rule is dangerous if it is TCP or
  "all protocols", its port range covers 22 or 3389, and its source is 0.0.0.0/0 or
  ::/0. Port ranges matter: a rule for 3000-4000 exposes 3389 and is caught.
- **EC2-001**: one call, `GetEbsEncryptionByDefault`, per region.
- **KMS-001**: only customer-managed, enabled, symmetric keys are evaluated, because
  AWS-managed keys rotate automatically and asymmetric keys can't use automatic
  rotation.

### `scanner/engine.py`
Gets the account ID with `sts:GetCallerIdentity`, picks checks (with optional
include/exclude lists), runs global checks once and regional checks per region. Any
AWS API error inside a check is caught and turned into an ERROR finding, so one
missing permission doesn't kill the whole scan and the gap is visible.

### `scanner/report.py` and `templates/report.html.j2`
Three writers. JSON is for machines (SIEM, dashboards). Markdown is for PRs and
tickets, with a deduplicated remediation section. HTML is a single file with inline
CSS, summary cards, and a findings table. Jinja2 autoescaping is forced on because
resource names come from AWS and could contain HTML. A unit test injects
`<script>` as a resource name and verifies it is escaped; that test actually caught
a bug during development where autoescape didn't apply to the `.html.j2` extension.

### `scanner/cli.py`
argparse front end. `--fail-on HIGH` returns exit code 2 if any HIGH or CRITICAL
check fails, so the tool can gate a pipeline.

### `policies/scanner-readonly-policy.json`
The exact 19 IAM actions the code calls. Nothing that writes or reads data.

### `tests/`
moto runs an in-memory fake AWS. Each test creates good and bad resources and
asserts the right PASS/FAIL. Where moto can't model something (root MFA on),
a tiny fake client is used. There are also tests for the engine's error handling,
the CLI exit codes, report generation, and HTML escaping.

### `.github/workflows/ci.yml`
On push/PR: ruff (lint and style, including the `S` security rules), bandit
(static security analysis of the package), pytest on Python 3.10 and 3.12.
`permissions: contents: read` keeps the workflow token minimal.

## Likely interview questions

**Why not just use Security Hub or Prowler?**
In production I would. This project shows I understand what those tools do under
the hood: which API answers which control, how to handle pagination and errors,
and how to scope permissions. It is also small enough to audit in an afternoon.

**How did you decide on least privilege?**
I listed every boto3 call in the code and mapped each one to its IAM action. The
policy has only those. `Resource: "*"` is unavoidable because list/describe APIs
don't support resource-level permissions. I'd deploy it as a role assumed via
SSO or GitHub OIDC rather than access keys.

**What happens if the scanner lacks a permission?**
The check's `ClientError` is caught in the engine and recorded as an ERROR finding
with the message, so the report shows exactly which control couldn't be evaluated.

**How do you test AWS code without an AWS account?**
moto patches botocore so calls hit an in-memory backend. For time-based logic I
inject the clock; for state moto can't model I use a fake client.

**How would you scale this to an AWS Organization?**
List accounts via `organizations:ListAccounts`, assume a read-only role in each
with STS, run the same engine per account concurrently (thread pool, since boto3
calls are I/O bound), and merge results. Add retries with adaptive backoff for
throttling.

**Why is GuardDuty labeled supplemental?**
It isn't in the CIS Foundations Benchmark; it comes from AWS Foundational Security
Best Practices. I kept the label honest rather than inventing a CIS number.

**What is log file validation in CloudTrail?**
CloudTrail writes hourly digest files with SHA-256 hashes, signed by AWS. You can
later prove whether log files were modified or deleted.

**Why do port ranges matter for the security group check?**
A rule like TCP 0-65535 from 0.0.0.0/0 exposes SSH even though it doesn't say "22".
The check tests whether 22 or 3389 falls inside the range, and treats protocol
`-1` (all traffic) as exposing everything.

**What are the known gaps?**
Single account only; S3 doesn't evaluate account-level Block Public Access or
bucket policies; only 12 controls; no auto-remediation by design (a scanner that
can write is a bigger blast radius).

**What security issues did you consider in the tool itself?**
Read-only permissions, HTML output escaping, no credentials in code or reports,
bandit in CI, and a minimal GitHub Actions token.

**How would you add auto-remediation safely?**
As a separate tool and role, with dry-run by default, explicit per-check opt-in,
and change logging, so the scanner's read-only role stays read-only.

## GCP provider

### What it adds, in plain English
The same scanner can now point at a Google Cloud project with
`--provider gcp --project <id>`. It runs 13 checks mapped to the CIS Google Cloud
Platform Foundation Benchmark (plus two from the CIS GKE Benchmark) and writes the
same JSON / Markdown / HTML reports.

- **`scanner/gcp/client.py`**: the only file that knows how to talk to Google. It
  defines a `GcpAdapter` interface with ten read-only methods ("give me the project
  IAM policy", "list buckets", "list firewall rules", ...). The real implementation
  uses Google's discovery-based API client with Application Default Credentials.
  Any API failure becomes a `GcpApiError`.
- **`scanner/gcp/fake.py`**: a fake adapter that just returns dicts from memory.
  Tests build a "good" and "bad" project with it, so nothing calls Google and no
  credentials exist in CI. This is the GCP equivalent of moto, written by hand.
- **`scanner/gcp/checks.py`**: the controls. They only ever call the adapter, so
  they don't care whether the data is real or fake.
  - IAM: no Owner/Editor for users or service accounts; service accounts with
    no admin roles; user-managed SA keys younger than 90 days (clock is injectable).
  - Logging: Data Access audit logs turned on for `allServices` with no exempted users.
  - Network: no `default` VPC; no firewall rule opening 22 or 3389 to the internet
    (port ranges like `3000-4000` and protocol `all` are handled).
  - Storage: no `allUsers` / `allAuthenticatedUsers` on buckets; uniform
    bucket-level access on.
  - Cloud SQL: no public IP; TLS required.
  - KMS: symmetric keys rotate at least every 90 days.
  - GKE: private nodes; legacy ABAC off.
- **`policies/gcp-scanner-role.yaml`**: a custom IAM role with exactly the 12
  permissions the adapter uses. Nothing that reads object data, creates keys, or
  decrypts.
- **`examples/sample-report-gcp/`**: a report from the fake adapter, clearly
  marked SYNTHETIC. I have not run this against a live GCP project and say so in
  the README.

### Likely GCP interview questions

**How is GCP IAM different from AWS IAM?**
In GCP you attach *bindings* (member + role) to a resource's IAM policy, and
policies inherit downward: organization, folder, project, resource. A role granted
at the org level applies to every project below it. AWS centers on identity-based
policy documents attached to users/roles plus resource policies. Roles in GCP are
basic (Owner/Editor/Viewer, too broad), predefined (per service), or custom. That's
why the scanner flags basic roles: Editor alone can change almost every resource.
A limitation I call out: the scanner only reads the project's own policy, so a
grant inherited from a folder wouldn't show up.

**Why are user-managed service account keys a risk, and what replaces them?**
A key is a long-lived JSON private key that works from anywhere until it's deleted,
and it tends to end up in repos, laptops, and CI variables. Google-managed keys are
rotated automatically and never leave Google. Better options are attaching the SA
to the workload, Workload Identity (GKE) or Workload Identity Federation (GitHub
Actions, AWS, Azure) to swap an external token for short-lived credentials, or
impersonation. The org policy `iam.disableServiceAccountKeyCreation` stops new
keys. The check flags anything older than 90 days, per CIS 1.7.

**What does uniform bucket-level access do?**
It turns off object ACLs so access to a bucket is controlled only by IAM. With
ACLs, an individual object can be public even if the bucket IAM looks clean, which
makes auditing hard. Uniform access gives one place to look, and it's also a
prerequisite for IAM Conditions on buckets. Pair it with Public Access Prevention
(`enforced`), which blocks `allUsers` grants outright. The public-bucket check
respects that: an `allUsers` binding on a bucket with PAP enforced isn't effective,
so it passes.

**What are VPC Service Controls and how do they relate to IAM?**
IAM answers "who can call this API". VPC Service Controls draw a *perimeter*
around projects and services (like Cloud Storage or BigQuery) and answer "from
where, and to where, can data move". Even a valid stolen credential can't copy data
from a bucket inside the perimeter to a bucket outside it, or call the API from the
internet unless an access level allows it. It's mainly a data-exfiltration control.
You usually start in dry-run mode to see what would be blocked. This scanner doesn't
check VPC-SC; I'd add it via the Access Context Manager API.

**How did you test GCP checks without a GCP account, and what's the risk?**
Checks depend on an adapter interface, not the Google client directly. Tests use an
in-memory fake that returns REST-shaped dicts, with one compliant and one
non-compliant case per check plus edge cases (port ranges, disabled rules, IPv6,
destroyed KMS keys). The risk is that my fake data might not match the real API
shape exactly; I matched field names to the public REST docs, but the next step
would be a smoke run against a throwaway project with the custom role, and
recording real responses as fixtures.
