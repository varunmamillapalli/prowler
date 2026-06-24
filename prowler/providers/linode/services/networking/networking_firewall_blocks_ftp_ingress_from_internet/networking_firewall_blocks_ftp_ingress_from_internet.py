from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.networking.lib.firewall_ingress import (
    firewall_allows_port_from_internet,
)
from prowler.providers.linode.services.networking.networking_client import (
    networking_client,
)


class networking_firewall_blocks_ftp_ingress_from_internet(Check):
    """Ensure Linode Firewalls block FTP ingress from the internet."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []
        target_ports = [20, 21]
        for fw in networking_client.firewalls:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=fw,
                resource_name=fw.label,
                resource_id=str(fw.id),
                region="global",
            )
            report.resource_tags = fw.tags
            if firewall_allows_port_from_internet(fw, target_ports):
                report.status = "FAIL"
                report.status_extended = (
                    f"Firewall '{fw.label}' allows FTP (port(s) [20, 21]) "
                    f"ingress from the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Firewall '{fw.label}' blocks FTP (port(s) [20, 21]) "
                    f"ingress from the internet."
                )
            findings.append(report)
        return findings
