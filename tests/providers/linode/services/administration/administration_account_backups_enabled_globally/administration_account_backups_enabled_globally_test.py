from unittest import mock

from prowler.providers.linode.services.administration.administration_service import (
    AccountSettings,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_administration_account_backups_enabled_globally:
    def test_no_settings(self):
        administration_client = mock.MagicMock()
        administration_client.account_settings = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally import (
                administration_account_backups_enabled_globally,
            )

            check = administration_account_backups_enabled_globally()
            result = check.execute()

            assert len(result) == 0

    def test_backups_enabled(self):
        administration_client = mock.MagicMock()
        administration_client.account_settings = AccountSettings(
            backups_enabled=True,
            managed=False,
            network_helper=True,
            object_storage="active",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally import (
                administration_account_backups_enabled_globally,
            )

            check = administration_account_backups_enabled_globally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_backups_disabled(self):
        administration_client = mock.MagicMock()
        administration_client.account_settings = AccountSettings(
            backups_enabled=False,
            managed=False,
            network_helper=True,
            object_storage="active",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_account_backups_enabled_globally.administration_account_backups_enabled_globally import (
                administration_account_backups_enabled_globally,
            )

            check = administration_account_backups_enabled_globally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
