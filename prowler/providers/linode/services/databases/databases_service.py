from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class MaintenanceWindow(BaseModel):
    """Model for database maintenance window settings."""

    day_of_week: int = 0
    duration: int = 0
    frequency: str = ""
    hour_of_day: int = 0
    pending: List = []


class Database(BaseModel):
    """Model for a Linode Managed Database instance."""

    id: int
    label: str
    engine: str = ""
    region: str = "global"
    status: str = ""
    encrypted: bool = False
    ssl_connection: bool = False
    allow_list: List[str] = []
    cluster_size: int = 1
    updates: Optional[MaintenanceWindow] = None
    tags: List[str] = []


class DatabasesService(LinodeService):
    """Service to interact with Linode Managed Databases."""

    def __init__(self, provider):
        super().__init__("databases", provider)
        self.databases: List[Database] = []
        self._describe_databases()

    def _describe_databases(self):
        """Fetch all managed database instances."""
        try:
            raw_instances = self.client.database.instances()
            for db in raw_instances:
                try:
                    region = "global"
                    try:
                        r = getattr(db, "region", None)
                        if r:
                            region = r.id if hasattr(r, "id") else str(r)
                    except Exception:
                        pass

                    updates = None
                    try:
                        upd = getattr(db, "updates", None)
                        if upd:
                            updates = MaintenanceWindow(
                                day_of_week=getattr(upd, "day_of_week", 0) or 0,
                                duration=getattr(upd, "duration", 0) or 0,
                                frequency=str(getattr(upd, "frequency", "") or ""),
                                hour_of_day=getattr(upd, "hour_of_day", 0) or 0,
                                pending=getattr(upd, "pending", []) or [],
                            )
                    except Exception:
                        pass

                    self.databases.append(
                        Database(
                            id=db.id,
                            label=db.label or f"db-{db.id}",
                            engine=str(getattr(db, "engine", "") or ""),
                            region=region,
                            status=str(getattr(db, "status", "") or ""),
                            encrypted=bool(getattr(db, "encrypted", False)),
                            ssl_connection=bool(getattr(db, "ssl_connection", False)),
                            allow_list=getattr(db, "allow_list", []) or [],
                            cluster_size=int(getattr(db, "cluster_size", 1) or 1),
                            updates=updates,
                            tags=getattr(db, "tags", []) or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"databases - Error processing database {db.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("databases", "databases:read_only", error)
