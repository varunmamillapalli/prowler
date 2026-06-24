from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.databases.databases_client import (
    databases_client,
)


class databases_allow_list_configured(Check):
    """Ensure managed database has an allow list configured to restrict access."""

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
            if db.allow_list:
                if "0.0.0.0/0" in db.allow_list or "::/0" in db.allow_list:
                    report.status = "FAIL"
                    report.status_extended = f"Database '{db.label}' allow list contains unrestricted access (0.0.0.0/0 or ::/0)."
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Database '{db.label}' has a restricted allow list configured."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database '{db.label}' does not have an allow list configured."
                )
            findings.append(report)
        return findings
