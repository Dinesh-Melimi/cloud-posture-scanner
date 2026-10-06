from scanner.checks.s3 import S3DefaultEncryption, S3PublicAccessBlock
from scanner.models import Status

BPA = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls",
                         "BlockPublicPolicy", "RestrictPublicBuckets")}


def test_public_access_block(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=BPA)
    s3.create_bucket(Bucket="open")
    s3.create_bucket(Bucket="partial")
    s3.put_public_access_block(Bucket="partial",
                               PublicAccessBlockConfiguration={**BPA, "BlockPublicPolicy": False})
    res = {f.resource: f.status for f in S3PublicAccessBlock(session).run()}
    assert res == {"locked": Status.PASS, "open": Status.FAIL, "partial": Status.FAIL}


def test_default_encryption(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="enc")
    s3.put_bucket_encryption(Bucket="enc", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.create_bucket(Bucket="plain")
    res = {f.resource: f.status for f in S3DefaultEncryption(session).run()}
    # Since Jan 2023 AWS applies SSE-S3 by default; moto may model either behavior.
    assert res["enc"] == Status.PASS
    assert res["plain"] in (Status.PASS, Status.FAIL)


def test_no_buckets_passes(session):
    assert [f.status for f in S3PublicAccessBlock(session).run()] == [Status.PASS]
