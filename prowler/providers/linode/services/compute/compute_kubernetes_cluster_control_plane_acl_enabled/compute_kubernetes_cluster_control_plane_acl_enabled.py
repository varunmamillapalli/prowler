from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.compute.compute_client import compute_client


class compute_kubernetes_cluster_control_plane_acl_enabled(Check):
    """Ensure LKE cluster has control plane ACL enabled."""

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
            if cluster.acl_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"LKE cluster '{cluster.label}' has control plane ACL enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"LKE cluster '{cluster.label}' does not have control plane ACL enabled."
            findings.append(report)
        return findings
