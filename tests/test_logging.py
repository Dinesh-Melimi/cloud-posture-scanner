from scanner.checks.logging import CloudTrailMultiRegion, GuardDutyEnabled
from scanner.models import Status


def _trail(session, multi, validation, start=True):
    session.client("s3").create_bucket(Bucket="trail-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name="org-trail", S3BucketName="trail-logs",
                    IsMultiRegionTrail=multi, EnableLogFileValidation=validation)
    if start:
        ct.start_logging(Name="org-trail")


def test_cloudtrail_none(session):
    assert CloudTrailMultiRegion(session).run()[0].status == Status.FAIL


def test_cloudtrail_compliant(session):
    _trail(session, multi=True, validation=True)
    assert CloudTrailMultiRegion(session).run()[0].status == Status.PASS


def test_cloudtrail_no_validation(session):
    _trail(session, multi=True, validation=False)
    assert CloudTrailMultiRegion(session).run()[0].status == Status.FAIL


def test_cloudtrail_single_region(session):
    _trail(session, multi=False, validation=True)
    assert CloudTrailMultiRegion(session).run()[0].status == Status.FAIL


def test_guardduty(session):
    check = GuardDutyEnabled(session, "us-east-1")
    assert check.run()[0].status == Status.FAIL
    session.client("guardduty").create_detector(Enable=True)
    assert check.run()[0].status == Status.PASS
