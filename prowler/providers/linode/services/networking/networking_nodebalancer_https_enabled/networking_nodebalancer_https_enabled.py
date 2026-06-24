from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.networking.networking_client import (
    networking_client,
)


class networking_nodebalancer_https_enabled(Check):
    """Ensure Linode NodeBalancer has at least one HTTPS config."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the networking_nodebalancer_https_enabled check.

        Iterates over all NodeBalancers and checks whether at least one
        config uses the HTTPS protocol.

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

            has_https = any(
                cfg.protocol in ("https", "tcp") and cfg.ssl_commonname
                for cfg in nb.configs
            )

            if not nb.configs:
                report.status = "FAIL"
                report.status_extended = f"NodeBalancer '{nb.label}' has no configs."
            elif has_https:
                report.status = "PASS"
                report.status_extended = f"NodeBalancer '{nb.label}' has HTTPS enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"NodeBalancer '{nb.label}' does not have HTTPS enabled."
                )

            findings.append(report)

        return findings
