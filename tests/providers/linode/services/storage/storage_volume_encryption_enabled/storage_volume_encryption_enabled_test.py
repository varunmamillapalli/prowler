from unittest import mock

from prowler.providers.linode.services.storage.storage_service import (
    Volume,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_storage_volume_encryption_enabled:
    def test_no_resources(self):
        storage_client = mock.MagicMock()
        storage_client.volumes = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled import (
                storage_volume_encryption_enabled,
            )

            check = storage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_pass(self):
        storage_client = mock.MagicMock()
        storage_client.volumes = [
            Volume(
                id=300,
                label="encrypted-vol",
                region="us-east",
                status="active",
                size=50,
                linode_id=1,
                encryption="enabled",
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled import (
                storage_volume_encryption_enabled,
            )

            check = storage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "300"
            assert result[0].resource_name == "encrypted-vol"

    def test_fail(self):
        storage_client = mock.MagicMock()
        storage_client.volumes = [
            Volume(
                id=301,
                label="unencrypted-vol",
                region="us-east",
                status="active",
                size=50,
                linode_id=1,
                encryption="disabled",
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.linode.services.storage.storage_volume_encryption_enabled.storage_volume_encryption_enabled import (
                storage_volume_encryption_enabled,
            )

            check = storage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
