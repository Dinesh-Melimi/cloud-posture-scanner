"""Generate the sample reports in examples/ against a moto-mocked account.

No real AWS account is touched. The fixture deliberately mixes compliant and
non-compliant resources so every report section is populated.

    python examples/generate_sample.py
"""

import os
from pathlib import Path

import boto3
from moto import mock_aws

from scanner.engine import run_scan
from scanner.report import write_reports

os.environ.update({"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                   "AWS_DEFAULT_REGION": "us-east-1", "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"})
R = "us-east-1"

with mock_aws():
    s = boto3.Session(region_name=R)
    iam, s3, ec2, kms = (s.client(x) for x in ("iam", "s3", "ec2", "kms"))
    iam.update_account_password_policy(MinimumPasswordLength=8)
    iam.create_user(UserName="ci-deployer")
    iam.create_user(UserName="legacy-admin")
    iam.attach_user_policy(UserName="legacy-admin",
                           PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    s3.create_bucket(Bucket="acme-public-assets")
    s3.create_bucket(Bucket="acme-audit-logs")
    s3.put_public_access_block(Bucket="acme-audit-logs", PublicAccessBlockConfiguration={
        k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                          "RestrictPublicBuckets")})
    s.client("cloudtrail").create_trail(Name="main-trail", S3BucketName="acme-audit-logs",
                                        IsMultiRegionTrail=True, EnableLogFileValidation=True)
    s.client("cloudtrail").start_logging(Name="main-trail")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="bastion", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    key = kms.create_key(Description="app-data")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key)
    kms.create_key(Description="old-key")

    result = run_scan(s, [R])
    for p in write_reports(result, Path(__file__).parent / "sample-report", ["json", "md", "html"]):
        print("wrote", p)
