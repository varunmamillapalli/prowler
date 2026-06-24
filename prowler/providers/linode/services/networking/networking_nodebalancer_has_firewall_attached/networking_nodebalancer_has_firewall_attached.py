from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.networking.networking_client import (
    networking_client,
)


class networking_nodebalancer_has_firewall_attached(Check):
    """Ensure Linode NodeBalancer has a Cloud Firewall attached."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the networking_nodebalancer_has_firewall_attached check.

        Iterates over all NodeBalancers and checks whether each one has
        at least one Cloud Firewall associated.

        Returns:
            list[CheckReportLinode]: A list of findings for each NodeBalancer.
        """
        findings = []

        for nb in networking_client.nodebalancers:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=nb,
                resource_name=nb.label,
                resource_id=str(nb.id),
                region=nb.region,
            )
            report.resource_tags = nb.tags

            if nb.has_firewall:
                report.status = "PASS"
                report.status_extended = (
                    f"NodeBalancer '{nb.label}' has a firewall attached."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"NodeBalancer '{nb.label}' does not have a firewall attached."
                )

            findings.append(report)

        return findings
