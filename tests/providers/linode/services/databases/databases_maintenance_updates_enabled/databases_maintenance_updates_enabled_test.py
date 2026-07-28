from unittest import mock

from prowler.providers.linode.services.databases.databases_service import (
    Database,
    MaintenanceWindow,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_databases_maintenance_updates_enabled:
    def test_no_databases(self):
        databases_client = mock.MagicMock()
        databases_client.databases = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled import (
                databases_maintenance_updates_enabled,
            )

            check = databases_maintenance_updates_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_maintenance_window_configured(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=600,
                label="maintained-db",
                engine="mysql/8.0",
                region="us-east",
                status="active",
                encrypted=True,
                ssl_connection=True,
                allow_list=["10.0.0.0/8"],
                cluster_size=3,
                updates=MaintenanceWindow(
                    day_of_week=1,
                    duration=3,
                    frequency="weekly",
                    hour_of_day=2,
                ),
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled import (
                databases_maintenance_updates_enabled,
            )

            check = databases_maintenance_updates_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "600"

    def test_maintenance_window_not_configured(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=601,
                label="no-maint-db",
                engine="mysql/8.0",
                region="us-east",
                status="active",
                encrypted=True,
                ssl_connection=True,
                allow_list=["10.0.0.0/8"],
                cluster_size=3,
                updates=None,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_maintenance_updates_enabled.databases_maintenance_updates_enabled import (
                databases_maintenance_updates_enabled,
            )

            check = databases_maintenance_updates_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
