from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.compute.compute_client import compute_client


class compute_kubernetes_cluster_acl_restricted(Check):
    """Ensure LKE cluster control plane ACL does not allow unrestricted access."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []
        for cluster in compute_client.lke_clusters:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=cluster,
                resource_name=cluster.label,
                resource_id=str(cluster.id),
                region=cluster.region,
            )
            report.resource_tags = cluster.tags
            if not cluster.acl_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"LKE cluster '{cluster.label}' does not have ACL enabled."
                )
            elif (
                "0.0.0.0/0" in cluster.acl_addresses_ipv4
                or "::/0" in cluster.acl_addresses_ipv6
            ):
                report.status = "FAIL"
                report.status_extended = f"LKE cluster '{cluster.label}' ACL allows unrestricted access (0.0.0.0/0 or ::/0)."
            else:
                report.status = "PASS"
                report.status_extended = f"LKE cluster '{cluster.label}' ACL is restricted to specific IP addresses."
            findings.append(report)
        return findings
