from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class FirewallRule(BaseModel):
    """Model for a single firewall rule."""

    protocol: str = "TCP"
    ports: str = ""  # e.g. "22", "1-65535", ""
    addresses_ipv4: List[str] = []
    addresses_ipv6: List[str] = []
    action: str = "ACCEPT"  # ACCEPT or DROP
    label: str = ""


class Firewall(BaseModel):
    """Model for a Linode Cloud Firewall."""

    id: int
    label: str
    status: str
    inbound_rules: List[FirewallRule] = []
    outbound_rules: List[FirewallRule] = []
    inbound_policy: str
    outbound_policy: str
    # None means the device count could not be determined (fetch failed), as
    # opposed to 0 which means the firewall genuinely has no devices attached.
    attached_devices_count: Optional[int] = None
    tags: List[str] = []


class NodeBalancerConfig(BaseModel):
    """Model for a single NodeBalancer config (port)."""

    id: int
    port: int = 80
    protocol: str = "http"
    algorithm: str = "roundrobin"
    stickiness: str = "none"
    check: str = "none"
    cipher_suite: str = "recommended"
    proxy_protocol: str = "none"
    ssl_commonname: str = ""
    ssl_fingerprint: str = ""


class NodeBalancer(BaseModel):
    """Model for a Linode NodeBalancer."""

    id: int
    label: str
    region: str = "global"
    status: str = "unknown"
    configs: List[NodeBalancerConfig] = []
    has_firewall: bool = False
    tags: List[str] = []


class NetworkingService(LinodeService):
    """Service to interact with Linode Cloud Firewalls and NodeBalancers."""

    def __init__(self, provider):
        super().__init__("networking", provider)
        self.firewalls: List[Firewall] = []
        self.nodebalancers: List[NodeBalancer] = []
        self._describe_firewalls()
        self._describe_nodebalancers()

    def _describe_firewalls(self):
        """Fetch all Linode Cloud Firewalls with their rules."""
        try:
            raw_firewalls = self.client.networking.firewalls()
            for fw in raw_firewalls:
                try:
                    inbound_rules = []
                    outbound_rules = []
                    inbound_policy = ""
                    outbound_policy = ""
                    attached_devices_count = None

                    try:
                        attached_devices_count = len(fw.devices)
                    except Exception as error:
                        logger.warning(
                            f"firewall - Unable to fetch devices for firewall {fw.id}: {error}"
                        )

                    try:
                        # linode_api4 Firewall objects expose rules as a mapped object.
                        rules = fw.rules
                        inbound_policy = getattr(rules, "inbound_policy", "")
                        outbound_policy = getattr(rules, "outbound_policy", "")
                        inbound = getattr(rules, "inbound", [])
                        outbound = getattr(rules, "outbound", [])

                        for rule in inbound:
                            addresses = getattr(rule, "addresses", None)
                            inbound_rules.append(
                                FirewallRule(
                                    protocol=(
                                        getattr(rule, "protocol", None) or "TCP"
                                    ).upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(addresses, "ipv4", []) or [],
                                    addresses_ipv6=getattr(addresses, "ipv6", []) or [],
                                    action=(
                                        getattr(rule, "action", None) or "ACCEPT"
                                    ).upper(),
                                    label=getattr(rule, "label", "") or "",
                                )
                            )
                        for rule in outbound:
                            addresses = getattr(rule, "addresses", None)
                            outbound_rules.append(
                                FirewallRule(
                                    protocol=(
                                        getattr(rule, "protocol", None) or "TCP"
                                    ).upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(addresses, "ipv4", []) or [],
                                    addresses_ipv6=getattr(addresses, "ipv6", []) or [],
                                    action=(
                                        getattr(rule, "action", None) or "ACCEPT"
                                    ).upper(),
                                    label=getattr(rule, "label", "") or "",
                                )
                            )
                    except Exception as error:
                        logger.warning(
                            f"firewall - Unable to fetch rules for firewall {fw.id}: {error}"
                        )

                    self.firewalls.append(
                        Firewall(
                            id=fw.id,
                            label=fw.label or f"firewall-{fw.id}",
                            status=fw.status or "unknown",
                            inbound_rules=inbound_rules,
                            outbound_rules=outbound_rules,
                            inbound_policy=inbound_policy,
                            outbound_policy=outbound_policy,
                            attached_devices_count=attached_devices_count,
                            tags=fw.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"firewall - Error processing firewall {fw.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("firewalls", "firewall:read_only", error)

    def _describe_nodebalancers(self):
        """Fetch all Linode NodeBalancers with their configs."""
        try:
            raw_nbs = self.client.nodebalancers()
            for nb in raw_nbs:
                try:
                    region = "global"
                    try:
                        r = getattr(nb, "region", None)
                        if r:
                            region = r.id if hasattr(r, "id") else str(r)
                    except Exception:
                        pass

                    configs = []
                    try:
                        for cfg in nb.configs:
                            configs.append(
                                NodeBalancerConfig(
                                    id=getattr(cfg, "id", 0),
                                    port=getattr(cfg, "port", 80) or 80,
                                    protocol=(
                                        getattr(cfg, "protocol", "http") or "http"
                                    ).lower(),
                                    algorithm=getattr(cfg, "algorithm", "roundrobin")
                                    or "roundrobin",
                                    stickiness=getattr(cfg, "stickiness", "none")
                                    or "none",
                                    check=getattr(cfg, "check", "none") or "none",
                                    cipher_suite=getattr(
                                        cfg, "cipher_suite", "recommended"
                                    )
                                    or "recommended",
                                    proxy_protocol=getattr(
                                        cfg, "proxy_protocol", "none"
                                    )
                                    or "none",
                                    ssl_commonname=getattr(cfg, "ssl_commonname", "")
                                    or "",
                                    ssl_fingerprint=getattr(cfg, "ssl_fingerprint", "")
                                    or "",
                                )
                            )
                    except Exception as error:
                        logger.warning(
                            f"nodebalancer - Unable to fetch configs for NodeBalancer {nb.id}: {error}"
                        )

                    has_firewall = False
                    try:
                        firewalls = nb.firewalls()
                        has_firewall = len(firewalls) > 0
                    except Exception as error:
                        logger.warning(
                            f"nodebalancer - Unable to fetch firewalls for NodeBalancer {nb.id}: {error}"
                        )

                    self.nodebalancers.append(
                        NodeBalancer(
                            id=nb.id,
                            label=nb.label or f"nodebalancer-{nb.id}",
                            region=region,
                            status=getattr(nb, "status", "unknown") or "unknown",
                            configs=configs,
                            has_firewall=has_firewall,
                            tags=nb.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"nodebalancer - Error processing NodeBalancer {nb.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("nodebalancers", "nodebalancers:read_only", error)
