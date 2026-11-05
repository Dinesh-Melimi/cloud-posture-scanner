"""Stand up a simulated AWS account for the responder to act on.

Uses moto's `mock_aws` context manager. Inside it, boto3 behaves like a real
account but nothing leaves the process. We seed the two things the breach
touches: the `ci-deploy` IAM user (with an access key) and the web-server EC2
instance (with an EBS volume), so containment has real resources to operate on.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import boto3
from moto import mock_aws

from .scenario import INSTANCE_ID


@contextmanager
def simulated_account(region: str = "us-east-1") -> Iterator[dict]:
    """Yield identifiers for the seeded resources while the mock is active."""
    with mock_aws():
        iam = boto3.client("iam", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)

        iam.create_user(UserName="ci-deploy")
        key = iam.create_access_key(UserName="ci-deploy")["AccessKey"]

        # A VPC + subnet so the instance lands somewhere the isolation group
        # can be created.
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        subnet = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
        images = ec2.describe_images().get("Images", [])
        ami = images[0]["ImageId"] if images else "ami-12345678"
        run = ec2.run_instances(
            ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
            SubnetId=subnet["SubnetId"])
        instance = run["Instances"][0]

        yield {
            "region": region,
            "user_name": "ci-deploy",
            "access_key_id": key["AccessKeyId"],
            "instance_id": instance["InstanceId"],
            "scenario_instance_id": INSTANCE_ID,
            "vpc_id": vpc["VpcId"],
        }
