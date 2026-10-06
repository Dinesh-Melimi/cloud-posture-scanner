from datetime import datetime, timedelta, timezone

from scanner.checks.iam import (
    ADMIN_POLICY_ARN,
    DirectAdminPolicy,
    PasswordPolicy,
    RootAccessKeys,
    RootMfa,
    UnusedCredentials,
)
from scanner.models import Status
from tests.conftest import FakeSession


class FakeIam:
    def __init__(self, mfa, keys):
        self.summary = {"AccountMFAEnabled": mfa, "AccountAccessKeysPresent": keys}

    def get_account_summary(self):
        return {"SummaryMap": self.summary}


def statuses(findings):
    return {f.status for f in findings}


def test_root_mfa_compliant():
    s = FakeSession(iam=FakeIam(mfa=1, keys=0))
    assert statuses(RootMfa(s).run()) == {Status.PASS}


def test_root_mfa_noncompliant(session):
    # moto reports AccountMFAEnabled=0 for a fresh account
    assert statuses(RootMfa(session).run()) == {Status.FAIL}


def test_root_access_keys_compliant(session):
    assert statuses(RootAccessKeys(session).run()) == {Status.PASS}


def test_root_access_keys_noncompliant():
    s = FakeSession(iam=FakeIam(mfa=1, keys=1))
    assert statuses(RootAccessKeys(s).run()) == {Status.FAIL}


def test_password_policy_missing(session):
    assert statuses(PasswordPolicy(session).run()) == {Status.FAIL}


def test_password_policy_weak(session):
    session.client("iam").update_account_password_policy(MinimumPasswordLength=8)
    [f] = PasswordPolicy(session).run()
    assert f.status == Status.FAIL and "minimum length" in f.message


def test_password_policy_strong(session):
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert statuses(PasswordPolicy(session).run()) == {Status.PASS}


def test_unused_credentials(session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    fresh = UnusedCredentials(session).run()
    assert statuses(fresh) == {Status.PASS}
    future = datetime.now(timezone.utc) + timedelta(days=120)
    stale = UnusedCredentials(session, now=future).run()
    [f] = [x for x in stale if x.resource == "alice"]
    assert f.status == Status.FAIL and "access_key_1" in f.message


def test_direct_admin_policy(session):
    iam = session.client("iam")
    iam.create_user(UserName="good")
    iam.create_user(UserName="bad")
    iam.attach_user_policy(UserName="bad", PolicyArn=ADMIN_POLICY_ARN)
    by_user = {f.resource: f.status for f in DirectAdminPolicy(session).run()}
    assert by_user == {"good": Status.PASS, "bad": Status.FAIL}
