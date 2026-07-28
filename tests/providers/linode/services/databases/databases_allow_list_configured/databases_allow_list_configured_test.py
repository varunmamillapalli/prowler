from unittest import mock

from prowler.providers.linode.services.databases.databases_service import (
    Database,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_databases_allow_list_configured:
    def test_no_resources(self):
        databases_client = mock.MagicMock()
        databases_client.databases = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured import (
                databases_allow_list_configured,
            )

            check = databases_allow_list_configured()
            result = check.execute()

            assert len(result) == 0

    def test_allow_list_configured(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=600,
                label="restricted-db",
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
                "prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured import (
                databases_allow_list_configured,
            )

            check = databases_allow_list_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "600"
            assert result[0].resource_name == "restricted-db"

    def test_allow_list_empty(self):
        databases_client = mock.MagicMock()
        databases_client.databases = [
            Database(
                id=601,
                label="open-db",
                engine="mysql/8.0",
                region="us-east",
                status="active",
                encrypted=True,
                ssl_connection=True,
                allow_list=[],
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
                "prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured.databases_client",
                new=databases_client,
            ),
        ):
            from prowler.providers.linode.services.databases.databases_allow_list_configured.databases_allow_list_configured import (
                databases_allow_list_configured,
            )

            check = databases_allow_list_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
