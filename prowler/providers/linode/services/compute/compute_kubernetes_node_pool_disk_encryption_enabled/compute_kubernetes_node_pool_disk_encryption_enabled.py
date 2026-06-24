from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.compute.compute_client import compute_client


class compute_kubernetes_node_pool_disk_encryption_enabled(Check):
    """Ensure LKE node pool disks have encryption enabled."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []
        for cluster in compute_client.lke_clusters:
            for pool in cluster.node_pools:
                report = CheckReportLinode(
                    metadata=self.metadata(),
                    resource=pool,
                    resource_name=f"{cluster.label}/pool-{pool.id}",
                    resource_id=str(pool.id),
                    region=cluster.region,
                )
                report.resource_tags = pool.tags
                if pool.disk_encryption == "enabled":
                    report.status = "PASS"
                    report.status_extended = f"Node pool {pool.id} in LKE cluster '{cluster.label}' has disk encryption enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Node pool {pool.id} in LKE cluster '{cluster.label}' does not have disk encryption enabled."
                findings.append(report)
        return findings
