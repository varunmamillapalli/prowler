from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class Volume(BaseModel):
    """Model for a Linode Block Storage Volume."""

    id: int
    label: str
    region: str = "global"
    status: str = "active"
    size: int = 0
    linode_id: Optional[int] = None
    encryption: str = "disabled"
    tags: List[str] = []


class ObjectStorageBucket(BaseModel):
    """Model for a Linode Object Storage Bucket."""

    label: str
    region: str = "global"
    hostname: str = ""
    objects: int = 0
    size: int = 0
    endpoint_type: str = ""
    acl: str = "private"
    cors_enabled: bool = False


class ObjectStorageKey(BaseModel):
    """Model for a Linode Object Storage Key."""

    id: int
    label: str
    limited: bool = False
    regions: List[str] = []
    bucket_access: Optional[List[dict]] = None


class StorageService(LinodeService):
    """Service to interact with Linode Block Storage and Object Storage."""

    def __init__(self, provider):
        super().__init__("storage", provider)
        self.volumes: List[Volume] = []
        self.object_buckets: List[ObjectStorageBucket] = []
        self.object_keys: List[ObjectStorageKey] = []
        self._describe_volumes()
        self._describe_object_buckets()
        self._describe_object_keys()

    def _describe_volumes(self):
        """Fetch all Linode Block Storage Volumes."""
        try:
            raw_volumes = self.client.volumes()
            for vol in raw_volumes:
                try:
                    region = "global"
                    try:
                        r = getattr(vol, "region", None)
                        if r:
                            region = r.id if hasattr(r, "id") else str(r)
                    except Exception:
                        pass

                    self.volumes.append(
                        Volume(
                            id=vol.id,
                            label=vol.label or f"volume-{vol.id}",
                            region=region,
                            status=getattr(vol, "status", "active") or "active",
                            size=getattr(vol, "size", 0) or 0,
                            linode_id=getattr(vol, "linode_id", None),
                            encryption=str(
                                getattr(vol, "encryption", "disabled") or "disabled"
                            ),
                            tags=vol.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"volume - Error processing volume {vol.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("volumes", "volumes:read_only", error)

    def _describe_object_buckets(self):
        """Fetch all Linode Object Storage Buckets with their ACL."""
        try:
            raw_buckets = self.client.object_storage.buckets()
            for bucket in raw_buckets:
                try:
                    region = "global"
                    try:
                        r = getattr(bucket, "region", None)
                        if r:
                            region = r.id if hasattr(r, "id") else str(r)
                    except Exception:
                        pass

                    acl = "private"
                    try:
                        access = bucket.access_get()
                        acl = getattr(access, "acl", "private") or "private"
                    except Exception as error:
                        logger.warning(
                            f"object_storage - Unable to fetch ACL for bucket {bucket.label}: {error}"
                        )

                    cors_enabled = False
                    try:
                        access = bucket.access_get()
                        cors_enabled = getattr(access, "cors_enabled", False) or False
                    except Exception:
                        pass

                    self.object_buckets.append(
                        ObjectStorageBucket(
                            label=bucket.label or "",
                            region=region,
                            hostname=getattr(bucket, "hostname", "") or "",
                            objects=getattr(bucket, "objects", 0) or 0,
                            size=getattr(bucket, "size", 0) or 0,
                            endpoint_type=str(
                                getattr(bucket, "endpoint_type", "") or ""
                            ),
                            acl=acl,
                            cors_enabled=cors_enabled,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"object_storage - Error processing bucket {getattr(bucket, 'label', 'unknown')}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error(
                "object storage buckets", "object_storage:read_only", error
            )

    def _describe_object_keys(self):
        """Fetch all Linode Object Storage Keys."""
        try:
            raw_keys = self.client.object_storage.keys()
            for key in raw_keys:
                try:
                    regions = []
                    try:
                        raw_regions = getattr(key, "regions", []) or []
                        for r in raw_regions:
                            if isinstance(r, dict):
                                regions.append(r.get("id", str(r)))
                            elif hasattr(r, "id"):
                                regions.append(r.id)
                            else:
                                regions.append(str(r))
                    except Exception:
                        pass

                    bucket_access = None
                    try:
                        ba = getattr(key, "bucket_access", None)
                        if ba:
                            bucket_access = [
                                (
                                    dict(item)
                                    if isinstance(item, dict)
                                    else {"raw": str(item)}
                                )
                                for item in ba
                            ]
                    except Exception:
                        pass

                    self.object_keys.append(
                        ObjectStorageKey(
                            id=key.id,
                            label=key.label or f"key-{key.id}",
                            limited=getattr(key, "limited", False) or False,
                            regions=regions,
                            bucket_access=bucket_access,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"object_storage - Error processing key {key.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error(
                "object storage keys", "object_storage:read_only", error
            )
