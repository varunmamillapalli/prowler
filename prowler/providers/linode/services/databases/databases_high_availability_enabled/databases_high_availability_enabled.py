from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.databases.databases_client import (
    databases_client,
)


class databases_high_availability_enabled(Check):
    """Ensure managed database has high availability enabled (cluster_size >= 3)."""

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
            if db.cluster_size >= 3:
                report.status = "PASS"
                report.status_extended = (
                    f"Database '{db.label}' has high availability enabled "
                    f"with cluster size {db.cluster_size}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database '{db.label}' does not have high availability enabled "
                    f"(cluster size is {db.cluster_size})."
                )
            findings.append(report)
        return findings
