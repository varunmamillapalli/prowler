from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class Instance(BaseModel):
    """Model for a Linode Instance."""

    id: int
    label: str
    region: str
    status: str
    backups_enabled: bool = False
    disk_encryption: str = "disabled"  # "enabled" or "disabled"
    watchdog_enabled: bool = False
    tags: List[str] = []


class LKENodePool(BaseModel):
    """Model for an LKE Node Pool."""

    id: int
    cluster_id: int
    node_count: int = 0
    disk_encryption: str = "disabled"
    autoscaler_enabled: bool = False
    tags: List[str] = []


class LKECluster(BaseModel):
    """Model for a Linode Kubernetes Engine cluster."""

    id: int
    label: str
    region: str = "global"
    k8s_version: str = ""
    tier: str = "standard"
    high_availability: bool = False
    acl_enabled: bool = False
    acl_addresses_ipv4: List[str] = []
    acl_addresses_ipv6: List[str] = []
    node_pools: List[LKENodePool] = []
    tags: List[str] = []


class ComputeService(LinodeService):
    """Service to interact with Linode Instances and LKE Clusters."""

    def __init__(self, provider):
        super().__init__("compute", provider)
        self.instances: List[Instance] = []
        self.lke_clusters: List[LKECluster] = []
        self._describe_instances()
        self._describe_lke_clusters()

    def _describe_instances(self):
        """Fetch all Linode instances with firewall and IP details."""
        # Optional --region filter. None scans all regions. Region-less services
        # do not call this, so they are always scanned.
        regions_filter = getattr(getattr(self, "provider", None), "regions", None)
        try:
            raw_instances = self.client.linode.instances()
            for inst in raw_instances:
                try:
                    region = (
                        inst.region.id
                        if hasattr(inst.region, "id")
                        else str(inst.region)
                    )
                    if regions_filter and region not in regions_filter:
                        continue

                    # Get backup status
                    backups_enabled = False
                    try:
                        backups = getattr(inst, "backups", None)
                        if backups:
                            backups_enabled = getattr(backups, "enabled", False)
                    except Exception as error:
                        logger.warning(
                            f"instance - Unable to fetch backup status for instance "
                            f"{inst.id}: {error}"
                        )

                    # Get disk encryption status
                    disk_encryption = "disabled"
                    try:
                        de = getattr(inst, "disk_encryption", None)
                        if de:
                            disk_encryption = str(de)
                    except Exception as error:
                        logger.warning(
                            f"instance - Unable to fetch disk encryption status for "
                            f"instance {inst.id}: {error}"
                        )

                    # Get watchdog status
                    watchdog_enabled = False
                    try:
                        watchdog_enabled = getattr(inst, "watchdog_enabled", False)
                    except Exception as error:
                        logger.warning(
                            f"instance - Unable to fetch watchdog status for instance "
                            f"{inst.id}: {error}"
                        )

                    self.instances.append(
                        Instance(
                            id=inst.id,
                            label=inst.label or f"linode-{inst.id}",
                            region=region,
                            status=inst.status or "unknown",
                            backups_enabled=backups_enabled,
                            disk_encryption=disk_encryption,
                            watchdog_enabled=watchdog_enabled,
                            tags=inst.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"instance - Error processing instance {inst.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("instances", "linodes:read_only", error)

    def _describe_lke_clusters(self):
        """Fetch all LKE clusters with their node pools and control plane config."""
        try:
            raw_clusters = self.client.lke.clusters()
            for cluster in raw_clusters:
                try:
                    region = "global"
                    try:
                        r = getattr(cluster, "region", None)
                        if r:
                            region = r.id if hasattr(r, "id") else str(r)
                    except Exception:
                        pass

                    k8s_version = ""
                    try:
                        kv = getattr(cluster, "k8s_version", None)
                        if kv:
                            k8s_version = kv.id if hasattr(kv, "id") else str(kv)
                    except Exception:
                        pass

                    # Control plane settings
                    high_availability = False
                    acl_enabled = False
                    acl_addresses_ipv4 = []
                    acl_addresses_ipv6 = []
                    try:
                        cp = getattr(cluster, "control_plane", None)
                        if cp:
                            ha = (
                                cp.get("high_availability")
                                if isinstance(cp, dict)
                                else getattr(cp, "high_availability", False)
                            )
                            high_availability = bool(ha)
                    except Exception:
                        pass

                    try:
                        acl = cluster.control_plane_acl
                        if acl:
                            acl_enabled = getattr(acl, "enabled", False) or False
                            addrs = getattr(acl, "addresses", None)
                            if addrs:
                                acl_addresses_ipv4 = getattr(addrs, "ipv4", []) or []
                                acl_addresses_ipv6 = getattr(addrs, "ipv6", []) or []
                    except Exception:
                        pass

                    # Node pools
                    node_pools = []
                    try:
                        for pool in cluster.pools:
                            autoscaler = getattr(pool, "autoscaler", None)
                            autoscaler_enabled = False
                            if autoscaler:
                                autoscaler_enabled = (
                                    autoscaler.get("enabled")
                                    if isinstance(autoscaler, dict)
                                    else getattr(autoscaler, "enabled", False)
                                ) or False

                            node_pools.append(
                                LKENodePool(
                                    id=pool.id,
                                    cluster_id=cluster.id,
                                    node_count=getattr(pool, "count", 0) or 0,
                                    disk_encryption=str(
                                        getattr(pool, "disk_encryption", "disabled")
                                        or "disabled"
                                    ),
                                    autoscaler_enabled=bool(autoscaler_enabled),
                                    tags=getattr(pool, "tags", []) or [],
                                )
                            )
                    except Exception as error:
                        logger.warning(
                            f"lke - Unable to fetch pools for cluster {cluster.id}: {error}"
                        )

                    self.lke_clusters.append(
                        LKECluster(
                            id=cluster.id,
                            label=cluster.label or f"lke-{cluster.id}",
                            region=region,
                            k8s_version=k8s_version,
                            tier=str(
                                getattr(cluster, "tier", "standard") or "standard"
                            ),
                            high_availability=high_availability,
                            acl_enabled=acl_enabled,
                            acl_addresses_ipv4=acl_addresses_ipv4,
                            acl_addresses_ipv6=acl_addresses_ipv6,
                            node_pools=node_pools,
                            tags=getattr(cluster, "tags", []) or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"lke - Error processing cluster {cluster.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("LKE clusters", "lke:read_only", error)
