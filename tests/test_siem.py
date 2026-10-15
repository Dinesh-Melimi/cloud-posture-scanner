import json

from scanner.checks.siem import CloudTrailSiemDelivery, FindingsForwardedToSiem, SecurityHubEnabled
from scanner.models import Status

R = "us-east-1"


def statuses(findings):
    return [f.status for f in findings]


def test_security_hub(session):
    assert statuses(SecurityHubEnabled(session, R).run()) == [Status.FAIL]
    session.client("securityhub", region_name=R).enable_security_hub()
    assert statuses(SecurityHubEnabled(session, R).run()) == [Status.PASS]


def _rule(session, name, sources, target=True, state="ENABLED"):
    ev = session.client("events", region_name=R)
    ev.put_rule(Name=name, EventPattern=json.dumps({"source": sources}), State=state)
    if target:
        q = session.client("sqs", region_name=R).create_queue(QueueName=name)["QueueUrl"]
        arn = session.client("sqs", region_name=R).get_queue_attributes(
            QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        ev.put_targets(Rule=name, Targets=[{"Id": "siem", "Arn": arn}])


def test_findings_forwarding(session):
    assert statuses(FindingsForwardedToSiem(session, R).run()) == [Status.FAIL, Status.FAIL]
    _rule(session, "gd-no-target", ["aws.guardduty"], target=False)
    _rule(session, "disabled", ["aws.securityhub"], state="DISABLED")
    assert statuses(FindingsForwardedToSiem(session, R).run()) == [Status.FAIL, Status.FAIL]
    _rule(session, "findings-to-siem", ["aws.guardduty", "aws.securityhub"])
    assert statuses(FindingsForwardedToSiem(session, R).run()) == [Status.PASS, Status.PASS]


def _trail(session):
    s3 = session.client("s3", region_name=R)
    s3.create_bucket(Bucket="trail-logs")
    session.client("cloudtrail", region_name=R).create_trail(Name="org", S3BucketName="trail-logs",
                                                             IsMultiRegionTrail=True)
    return s3


def test_cloudtrail_delivery_via_s3_notification(session):
    assert statuses(CloudTrailSiemDelivery(session).run()) == [Status.FAIL]  # no trail
    s3 = _trail(session)
    assert statuses(CloudTrailSiemDelivery(session).run()) == [Status.FAIL]  # S3 only, nothing pulls it
    sqs = session.client("sqs", region_name=R)
    url = sqs.create_queue(QueueName="siem-cloudtrail")["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    s3.put_bucket_notification_configuration(Bucket="trail-logs", NotificationConfiguration={
        "QueueConfigurations": [{"QueueArn": arn, "Events": ["s3:ObjectCreated:*"]}]})
    assert statuses(CloudTrailSiemDelivery(session).run()) == [Status.PASS]
