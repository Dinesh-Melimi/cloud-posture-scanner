# AWS Cloud Posture Report

- **Account:** 123456789012
- **Regions:** us-east-1
- **Scanned at:** 2026-10-06T21:03:04+00:00
- **Score:** 47.4% (9/19 passed, 10 failed, 0 errors)

## Severity summary

| Severity | Fail | Pass | Error |
|---|---|---|---|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 3 | 5 | 0 |
| MEDIUM | 6 | 3 | 0 |
| LOW | 0 | 0 | 0 |

## Findings

| Status | Severity | ID | CIS | Resource | Region | Detail |
|---|---|---|---|---|---|---|
| FAIL | CRITICAL | IAM-001 | CIS 1.5 | root | global | Root MFA is NOT enabled. |
| FAIL | HIGH | IAM-005 | CIS 1.15, 1.16 | legacy-admin | global | AdministratorAccess attached directly to user. |
| FAIL | HIGH | NET-001 | CIS 5.2, 5.3 | sg-e41c17669814310c7 (bastion) | us-east-1 | Ports open to the internet: [22] |
| FAIL | HIGH | S3-001 | CIS 2.1.4 | acme-public-assets | global | Public access block missing or incomplete. |
| FAIL | MEDIUM | EC2-001 | CIS 2.2.1 | ebs-default | us-east-1 | EBS encryption by default disabled. |
| FAIL | MEDIUM | IAM-003 | CIS 1.8, 1.9 | account | global | Password policy weak: minimum length < 14, reuse prevention < 24 |
| FAIL | MEDIUM | KMS-001 | CIS 3.6 | 9b0be007-3302-4bb3-8421-4c9b5305f195 | us-east-1 | Rotation disabled. |
| FAIL | MEDIUM | LOG-002 | AWS FSBP GuardDuty.1 (supplemental) | guardduty | us-east-1 | No enabled GuardDuty detector in region. |
| FAIL | MEDIUM | S3-002 | CIS 2.1.1 (v1.4) | acme-public-assets | global | No default encryption configured. |
| FAIL | MEDIUM | S3-002 | CIS 2.1.1 (v1.4) | acme-audit-logs | global | No default encryption configured. |
| PASS | CRITICAL | IAM-002 | CIS 1.4 | root | global | Root has no access keys. |
| PASS | HIGH | IAM-005 | CIS 1.15, 1.16 | ci-deployer | global | No admin policy attached directly. |
| PASS | HIGH | LOG-001 | CIS 3.1, 3.2 | main-trail | global | Multi-region trail logging with log file validation. |
| PASS | HIGH | NET-001 | CIS 5.2, 5.3 | sg-33abcd18b397b0534 (default) | us-east-1 | No world-open SSH/RDP. |
| PASS | HIGH | NET-001 | CIS 5.2, 5.3 | sg-b84f5ff88b9a49740 (default) | us-east-1 | No world-open SSH/RDP. |
| PASS | HIGH | S3-001 | CIS 2.1.4 | acme-audit-logs | global | All four public access block settings enabled. |
| PASS | MEDIUM | IAM-004 | CIS 1.12 | ci-deployer | global | No stale credentials. |
| PASS | MEDIUM | IAM-004 | CIS 1.12 | legacy-admin | global | No stale credentials. |
| PASS | MEDIUM | KMS-001 | CIS 3.6 | 85424210-67cb-4487-b12d-b5849d757574 | us-east-1 | Rotation enabled. |

## Remediation

### IAM-001 - Root account has MFA enabled

`Sign in as root, open Security credentials, and assign a hardware or virtual MFA device to the root user.`

### IAM-005 - No IAM users have AdministratorAccess attached directly

`Detach admin policies from users; grant privileges through groups or assumable roles with least-privilege policies.`

### NET-001 - No security groups allow 0.0.0.0/0 or ::/0 to SSH/RDP

`Remove the world-open ingress rule and restrict SSH/RDP to known CIDRs, or use SSM Session Manager instead of open admin ports.`

### S3-001 - S3 Block Public Access enabled on buckets

`aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`

### EC2-001 - EBS encryption by default is enabled

`aws ec2 enable-ebs-encryption-by-default --region <region>`

### IAM-003 - IAM password policy meets minimum strength

`aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24`

### KMS-001 - Customer-managed symmetric KMS keys have rotation enabled

`aws kms enable-key-rotation --key-id <key-id>`

### LOG-002 - GuardDuty is enabled in the region

`aws guardduty create-detector --enable --region <region>`

### S3-002 - S3 buckets have default encryption configured

`aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'`

