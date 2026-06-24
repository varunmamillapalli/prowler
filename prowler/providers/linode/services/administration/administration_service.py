from typing import List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class User(BaseModel):
    """Model for a Linode account user."""

    username: str
    email: str = ""
    tfa_enabled: bool = False
    restricted: bool = False


class AccountSettings(BaseModel):
    """Model for Linode account settings."""

    backups_enabled: bool = False
    managed: bool = False
    network_helper: bool = False
    object_storage: Optional[str] = None


class AdministrationService(LinodeService):
    """Service to interact with Linode Account Users and Settings."""

    def __init__(self, provider):
        super().__init__("administration", provider)
        self.users: List[User] = []
        self.account_settings: Optional[AccountSettings] = None
        self._describe_users()
        self._describe_account_settings()

    def _describe_users(self):
        """Fetch all Linode account users."""
        try:
            raw_users = self.client.account.users()
            for user in raw_users:
                try:
                    self.users.append(
                        User(
                            username=getattr(user, "username", "") or "",
                            email=getattr(user, "email", "") or "",
                            tfa_enabled=getattr(user, "tfa_enabled", False) or False,
                            restricted=getattr(user, "restricted", False) or False,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"account - Error processing user {getattr(user, 'username', 'unknown')}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("account users", "account:read_only", error)

    def _describe_account_settings(self):
        """Fetch Linode account settings."""
        try:
            settings = self.client.account.settings()
            self.account_settings = AccountSettings(
                backups_enabled=getattr(settings, "backups_enabled", False) or False,
                managed=getattr(settings, "managed", False) or False,
                network_helper=getattr(settings, "network_helper", False) or False,
                object_storage=str(getattr(settings, "object_storage", "") or ""),
            )
        except Exception as error:
            self._log_fetch_error("account settings", "account:read_only", error)
