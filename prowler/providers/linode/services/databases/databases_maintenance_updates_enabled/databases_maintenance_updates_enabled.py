from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.databases.databases_client import (
    databases_client,
)


class databases_maintenance_updates_enabled(Check):
    """Ensure managed database has maintenance updates configured."""

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
            if db.updates and db.updates.frequency:
                report.status = "PASS"
                report.status_extended = (
                    f"Database '{db.label}' has maintenance updates configured "
                    f"with frequency '{db.updates.frequency}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Database '{db.label}' does not have maintenance updates configured."
            findings.append(report)
        return findings
