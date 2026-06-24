from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.administration.administration_client import (
    administration_client,
)


class administration_account_backups_enabled_globally(Check):
    """Ensure Linode account has automatic backups enabled globally."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the administration_account_backups_enabled_globally check.

        Checks whether the account-wide automatic backups setting is enabled.

        Returns:
            list[CheckReportLinode]: A list with a single finding for the account.
        """
        findings = []

        if administration_client.account_settings is None:
            return findings

        settings = administration_client.account_settings

        report = CheckReportLinode(
            metadata=self.metadata(),
            resource=settings,
            resource_name="Account Settings",
            resource_id="account-settings",
            region="global",
        )

        if settings.backups_enabled:
            report.status = "PASS"
            report.status_extended = "Account-wide automatic backups are enabled."
        else:
            report.status = "FAIL"
            report.status_extended = "Account-wide automatic backups are not enabled."

        findings.append(report)

        return findings
