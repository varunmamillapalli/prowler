from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.databases.databases_client import (
    databases_client,
)


class databases_disk_encryption_enabled(Check):
    """Ensure managed database has disk encryption enabled."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []
        for db in databases_client.databases:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=db,
                resource_name=db.label,
                resource_id=str(db.id),
                region=db.region,
            )
            report.resource_tags = db.tags
            if db.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Database '{db.label}' has disk encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database '{db.label}' does not have disk encryption enabled."
                )
            findings.append(report)
        return findings
