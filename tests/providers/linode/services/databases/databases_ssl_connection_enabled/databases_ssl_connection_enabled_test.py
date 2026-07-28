from unittest import mock

from prowler.providers.linode.services.databases.databases_service import (
    Database,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_databases_ssl_connection_enabled:
    def test_no_resources(self):
        databases_client = mock.MagicMock()
        databases_client.databases = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled import (
                databases_ssl_connection_enabled,
            )

            check = databases_ssl_connection_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_ssl_connection_enabled(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=600,
                label="ssl-db",
                engine="mysql/8.0",
                region="us-east",
                status="active",
                encrypted=True,
                ssl_connection=True,
                allow_list=["10.0.0.0/8"],
                cluster_size=3,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled import (
                databases_ssl_connection_enabled,
            )

            check = databases_ssl_connection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "600"
            assert result[0].resource_name == "ssl-db"

    def test_ssl_connection_disabled(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=601,
                label="no-ssl-db",
                engine="mysql/8.0",
                region="us-east",
                status="active",
                encrypted=True,
                ssl_connection=False,
                allow_list=["10.0.0.0/8"],
                cluster_size=3,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_ssl_connection_enabled.databases_ssl_connection_enabled import (
                databases_ssl_connection_enabled,
            )

            check = databases_ssl_connection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
