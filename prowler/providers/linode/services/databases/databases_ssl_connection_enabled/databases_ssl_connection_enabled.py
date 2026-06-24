from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.databases.databases_client import (
    databases_client,
)


class databases_ssl_connection_enabled(Check):
    """Ensure managed database has SSL connection enabled."""

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
            if db.ssl_connection:
                report.status = "PASS"
                report.status_extended = (
                    f"Database '{db.label}' has SSL connection enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database '{db.label}' does not have SSL connection enabled."
                )
            findings.append(report)
        return findings
