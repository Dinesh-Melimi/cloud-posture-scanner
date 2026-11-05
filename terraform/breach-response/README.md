# Breach-response stack (real AWS)

This is the live-account version of the lab's defensive wiring. It turns on
GuardDuty, deploys a least-privilege responder Lambda, and routes GuardDuty
findings to it through EventBridge. When a credential-theft or S3-exfiltration
finding arrives, the Lambda runs the same containment as `breachlab/respond.py`:
snapshot the instance, revoke access keys, quarantine the principal with a
deny-all policy, and isolate the instance in a no-egress security group.

## What it does and does not create

- **Creates:** a GuardDuty detector, an IAM role scoped to the containment
  actions only, the responder Lambda, and the EventBridge rule and permission.
- **Does not create:** anything deliberately vulnerable. The "attacker" side of
  the lab lives entirely in the offline telemetry replay (`python -m breachlab
  run`); this stack is only the detection and response side.

## Packaging the Lambda

The Lambda imports the `breachlab` package, so the deployment zip needs both
`lambda/handler.py` and the `breachlab/` package. Before `terraform apply`:

```bash
# from the repo root
cp -r breachlab terraform/breach-response/lambda/breachlab
```

`archive_file` then zips the whole `lambda/` directory. (Keep the copy out of
version control; it is a build step.)

## Deploy

```bash
cd terraform/breach-response
terraform init
terraform plan      # read every line before applying
terraform apply
```

Use a sandbox account you own, and tear it down with `terraform destroy` when
you are done.

## A note on validation

This configuration is hand-reviewed. It was authored in an environment without
the Terraform CLI, so it has **not** been run through `terraform validate` or
`plan` here. Run both yourself against your account before relying on it, and
pin the provider version to whatever your tooling resolves.
