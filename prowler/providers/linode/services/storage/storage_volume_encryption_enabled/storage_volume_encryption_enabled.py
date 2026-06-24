from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.storage.storage_client import storage_client


class storage_volume_encryption_enabled(Check):
    """Ensure Block Storage volume has disk encryption enabled."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []
        for vol in storage_client.volumes:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=vol,
                resource_name=vol.label,
                resource_id=str(vol.id),
                region=vol.region,
            )
            report.resource_tags = vol.tags
            if vol.encryption == "enabled":
                report.status = "PASS"
                report.status_extended = (
                    f"Volume '{vol.label}' has disk encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Volume '{vol.label}' does not have disk encryption enabled."
                )
            findings.append(report)
        return findings
