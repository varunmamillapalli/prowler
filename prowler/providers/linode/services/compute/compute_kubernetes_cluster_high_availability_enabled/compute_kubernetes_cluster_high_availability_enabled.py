from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.compute.compute_client import compute_client


class compute_kubernetes_cluster_high_availability_enabled(Check):
    """Ensure LKE cluster control plane has high availability enabled."""

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
            if cluster.high_availability:
                report.status = "PASS"
                report.status_extended = (
                    f"LKE cluster '{cluster.label}' has high availability enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"LKE cluster '{cluster.label}' does not have high availability enabled."
            findings.append(report)
        return findings
