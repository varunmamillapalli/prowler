from unittest import mock

from prowler.providers.linode.services.administration.administration_service import (
    User,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_administration_user_access_restricted:
    def test_no_resources(self):
        administration_client = mock.MagicMock()
        administration_client.users = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted import (
                administration_user_access_restricted,
            )

            check = administration_user_access_restricted()
            result = check.execute()

            assert len(result) == 0

    def test_user_access_restricted(self):
        administration_client = mock.MagicMock()
        administration_client.users = [
            User(
                username="restricted-user",
                email="user@example.com",
                tfa_enabled=True,
                restricted=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted import (
                administration_user_access_restricted,
            )

            check = administration_user_access_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "restricted-user"
            assert result[0].resource_name == "restricted-user"

    def test_user_access_unrestricted(self):
        administration_client = mock.MagicMock()
        administration_client.users = [
            User(
                username="unrestricted-user",
                email="admin@example.com",
                tfa_enabled=True,
                restricted=False,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted.administration_client",
                new=administration_client,
            ),
        ):
            from prowler.providers.linode.services.administration.administration_user_access_restricted.administration_user_access_restricted import (
                administration_user_access_restricted,
            )

            check = administration_user_access_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
