from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.administration.administration_client import (
    administration_client,
)


class administration_user_access_restricted(Check):
    """Ensure Linode account users have restricted access (least privilege)."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the administration_user_access_restricted check.

        Iterates over all account users and checks whether each user has
        restricted access enabled.

        Returns:
            list[CheckReportLinode]: A list of findings for each user.
        """
        findings = []

        for user in administration_client.users:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.username,
                resource_id=user.username,
                region="global",
            )

            if user.restricted:
                report.status = "PASS"
                report.status_extended = (
                    f"User '{user.username}' has restricted access."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"User '{user.username}' has unrestricted (full) access to the account."

            findings.append(report)

        return findings
