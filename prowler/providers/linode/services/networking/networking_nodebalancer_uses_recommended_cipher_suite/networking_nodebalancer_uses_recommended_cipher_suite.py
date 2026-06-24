from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.networking.networking_client import (
    networking_client,
)


class networking_nodebalancer_uses_recommended_cipher_suite(Check):
    """Ensure Linode NodeBalancer HTTPS configs use the recommended cipher suite."""

    def execute(self) -> list[CheckReportLinode]:
        """Execute the networking_nodebalancer_uses_recommended_cipher_suite check.

        Iterates over all NodeBalancers and checks whether HTTPS configs
        use the 'recommended' cipher suite instead of 'legacy'.

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

            legacy_configs = [
                cfg
                for cfg in nb.configs
                if cfg.protocol in ("https",) and cfg.cipher_suite != "recommended"
            ]

            if not nb.configs:
                report.status = "FAIL"
                report.status_extended = f"NodeBalancer '{nb.label}' has no configs."
            elif legacy_configs:
                report.status = "FAIL"
                report.status_extended = (
                    f"NodeBalancer '{nb.label}' has {len(legacy_configs)} HTTPS config(s) "
                    f"not using the recommended cipher suite."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"NodeBalancer '{nb.label}' uses the recommended cipher suite on all HTTPS configs."

            findings.append(report)

        return findings
