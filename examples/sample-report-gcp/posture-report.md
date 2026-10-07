# GCP Cloud Posture Report

> **SYNTHETIC SAMPLE: generated from an in-memory fake adapter (examples/generate_sample_gcp.py). No real GCP project was scanned.**

- **Project:** acme-synthetic-demo
- **Locations:** global, us-central1, us-central1-a
- **Scanned at:** 2026-10-07T15:04:01+00:00
- **Score:** 44.0% (11/25 passed, 14 failed, 0 errors)

## Severity summary

| Severity | Fail | Pass | Error |
|---|---|---|---|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 7 | 6 | 0 |
| MEDIUM | 6 | 4 | 0 |
| LOW | 0 | 0 | 0 |

## Findings

| Status | Severity | ID | CIS | Resource | Region | Detail |
|---|---|---|---|---|---|---|
| FAIL | CRITICAL | GCP-GCS-001 | CIS GCP 5.1 | acme-public-assets | us-central1 | Public IAM bindings: allUsers -> roles/storage.objectViewer. |
| FAIL | HIGH | GCP-GKE-002 | CIS GKE 5.8.3 | sandbox-gke | us-central1-a | Legacy ABAC enabled; RBAC can be bypassed. |
| FAIL | HIGH | GCP-IAM-001 | CIS GCP 1.5 (extended to users) | user:contractor@example.com | global | Granted primitive role roles/editor on the project. |
| FAIL | HIGH | GCP-IAM-001 | CIS GCP 1.5 (extended to users) | serviceAccount:etl@acme-synthetic-demo.iam.gserviceaccount.com | global | Granted primitive role roles/editor on the project. |
| FAIL | HIGH | GCP-IAM-002 | CIS GCP 1.5 | etl@acme-synthetic-demo.iam.gserviceaccount.com | global | Holds admin role(s): roles/editor. |
| FAIL | HIGH | GCP-NET-002 | CIS GCP 3.6, 3.7 | default-allow-ssh | global | Open to the internet on SSH/22. |
| FAIL | HIGH | GCP-SQL-001 | CIS GCP 6.6 | orders-db | us-central1 | Instance has a public IPv4 address. Authorized networks include 0.0.0.0/0. |
| FAIL | HIGH | GCP-SQL-002 | CIS GCP 6.4 | orders-db | us-central1 | Unencrypted connections allowed (ALLOW_UNENCRYPTED_AND_ENCRYPTED). |
| FAIL | MEDIUM | GCP-GCS-002 | CIS GCP 5.2 | acme-public-assets | us-central1 | Fine-grained object ACLs are still active. |
| FAIL | MEDIUM | GCP-GKE-001 | CIS GKE 5.6.5 | sandbox-gke | us-central1-a | Nodes have public IP addresses. |
| FAIL | MEDIUM | GCP-IAM-003 | CIS GCP 1.7 | etl@acme-synthetic-demo.iam.gserviceaccount.com/3f9a1c | global | User-managed key is 214 days old. |
| FAIL | MEDIUM | GCP-KMS-001 | CIS GCP 1.10 | projects/acme-synthetic-demo/locations/us-central1/keyRings/app/cryptoKeys/legacy-key | us-central1 | No automatic rotation schedule. |
| FAIL | MEDIUM | GCP-LOG-001 | CIS GCP 2.1 | acme-synthetic-demo | global | allServices audit config missing ['DATA_READ', 'DATA_WRITE']. |
| FAIL | MEDIUM | GCP-NET-001 | CIS GCP 3.1 | default | global | Default network (with permissive pre-built rules) exists. |
| PASS | CRITICAL | GCP-GCS-001 | CIS GCP 5.1 | acme-audit-logs | us-central1 | No allUsers/allAuthenticatedUsers bindings in effect. |
| PASS | HIGH | GCP-GKE-002 | CIS GKE 5.8.3 | prod-gke | us-central1 | Legacy ABAC disabled; RBAC only. |
| PASS | HIGH | GCP-IAM-002 | CIS GCP 1.5 | web@acme-synthetic-demo.iam.gserviceaccount.com | global | No admin roles at project level. |
| PASS | HIGH | GCP-NET-002 | CIS GCP 3.6, 3.7 | allow-iap-admin | global | Source ranges are restricted. |
| PASS | HIGH | GCP-NET-002 | CIS GCP 3.6, 3.7 | allow-https | global | Internet-facing, but not on 22/3389. |
| PASS | HIGH | GCP-SQL-001 | CIS GCP 6.6 | analytics-db | us-central1 | Private IP only. |
| PASS | HIGH | GCP-SQL-002 | CIS GCP 6.4 | analytics-db | us-central1 | TLS required (ENCRYPTED_ONLY). |
| PASS | MEDIUM | GCP-GCS-002 | CIS GCP 5.2 | acme-audit-logs | us-central1 | Uniform bucket-level access enabled; ACLs disabled. |
| PASS | MEDIUM | GCP-GKE-001 | CIS GKE 5.6.5 | prod-gke | us-central1 | Nodes have internal IPs only. |
| PASS | MEDIUM | GCP-IAM-003 | CIS GCP 1.7 | web@acme-synthetic-demo.iam.gserviceaccount.com/b71e02 | global | User-managed key is 12 days old. |
| PASS | MEDIUM | GCP-KMS-001 | CIS GCP 1.10 | projects/acme-synthetic-demo/locations/us-central1/keyRings/app/cryptoKeys/app-data | us-central1 | Rotates every 90 days. |

## Remediation

### GCP-GCS-001 - Cloud Storage buckets are not anonymously or publicly accessible

`gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allUsers --role=<role>; enforce the constraints/storage.publicAccessPrevention org policy`

### GCP-GKE-002 - GKE legacy authorization (ABAC) is disabled

`gcloud container clusters update <cluster> --location=<loc> --no-enable-legacy-authorization`

### GCP-IAM-001 - No primitive Owner/Editor roles granted to users or service accounts at project level

`gcloud projects remove-iam-policy-binding <project> --member=<member> --role=roles/editor and grant a narrower predefined role instead`

### GCP-IAM-002 - Service accounts do not hold admin privileges

`gcloud projects remove-iam-policy-binding <project> --member=serviceAccount:<email> --role=<admin role>`

### GCP-NET-002 - No firewall rule allows 0.0.0.0/0 to SSH (22) or RDP (3389)

`gcloud compute firewall-rules update <rule> --source-ranges=<trusted CIDR> (or delete it and use IAP TCP forwarding: 35.235.240.0/20)`

### GCP-SQL-001 - Cloud SQL instances do not have public IP addresses

`Configure private IP (Private Services Access), then: gcloud sql instances patch <instance> --no-assign-ip`

### GCP-SQL-002 - Cloud SQL instances require SSL/TLS for incoming connections

`gcloud sql instances patch <instance> --ssl-mode=ENCRYPTED_ONLY`

### GCP-GCS-002 - Cloud Storage buckets have uniform bucket-level access enabled

`gcloud storage buckets update gs://<bucket> --uniform-bucket-level-access`

### GCP-GKE-001 - GKE clusters use private nodes

`gcloud container clusters update <cluster> --location=<loc> --enable-private-nodes (older clusters may need re-creation with --enable-private-nodes)`

### GCP-IAM-003 - User-managed service account keys are rotated within 90 days

`gcloud iam service-accounts keys create new.json --iam-account=<email>; switch callers; gcloud iam service-accounts keys delete <key-id> --iam-account=<email>. Prefer Workload Identity / impersonation over keys.`

### GCP-KMS-001 - Cloud KMS symmetric keys rotate at least every 90 days

`gcloud kms keys update <key> --keyring=<ring> --location=<loc> --rotation-period=90d --next-rotation-time=<RFC3339>`

### GCP-LOG-001 - Cloud Audit Logs Data Access logging enabled for all services

`gcloud projects get-iam-policy <project> > p.yaml; add auditConfigs for service allServices with ADMIN_READ, DATA_READ, DATA_WRITE and no exemptedMembers; gcloud projects set-iam-policy <project> p.yaml`

### GCP-NET-001 - The default VPC network does not exist

`Move workloads to a custom VPC, then: gcloud compute networks delete default`

