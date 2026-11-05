"""Cloud breach detection-and-response lab.

This package replays the *telemetry* a cloud attack leaves behind (CloudTrail,
GuardDuty, VPC flow logs), runs detection-as-code over it, triggers automated
containment against a simulated AWS account, and writes an incident report.

It does not contain working exploit code. Each attack step is represented by
the log records it would produce, the way detection-engineering datasets such
as Splunk Attack Range or Stratus Red Team work. The value of the lab is on the
defensive side: catching the activity and responding to it.
"""

__version__ = "0.1.0"
