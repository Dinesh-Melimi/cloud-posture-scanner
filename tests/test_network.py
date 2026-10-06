from scanner.checks.network import EbsDefaultEncryption, KmsKeyRotation, OpenAdminPorts
from scanner.models import Status

R = "us-east-1"


def test_open_admin_ports(session):
    ec2 = session.client("ec2", region_name=R)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    bad = ec2.create_security_group(GroupName="bad", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bad, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    v6 = ec2.create_security_group(GroupName="v6", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=v6, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    good = ec2.create_security_group(GroupName="good", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=good, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}, {
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    res = {f.resource.split()[0]: f for f in OpenAdminPorts(session, R).run()}
    assert res[bad].status == Status.FAIL and "22" in res[bad].message
    assert res[v6].status == Status.FAIL and "3389" in res[v6].message
    assert res[good].status == Status.PASS


def test_ebs_default_encryption(session):
    check = EbsDefaultEncryption(session, R)
    assert check.run()[0].status == Status.FAIL
    session.client("ec2", region_name=R).enable_ebs_encryption_by_default()
    assert check.run()[0].status == Status.PASS


def test_kms_rotation(session):
    kms = session.client("kms", region_name=R)
    on = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=on)
    off = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")  # skipped: asymmetric
    res = {f.resource: f.status for f in KmsKeyRotation(session, R).run()}
    assert res == {on: Status.PASS, off: Status.FAIL}
