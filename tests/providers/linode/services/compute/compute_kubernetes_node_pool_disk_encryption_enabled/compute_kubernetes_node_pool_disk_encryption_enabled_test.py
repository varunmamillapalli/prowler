from unittest import mock

from prowler.providers.linode.services.compute.compute_service import (
    LKECluster,
    LKENodePool,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_compute_kubernetes_node_pool_disk_encryption_enabled:
    def test_no_clusters(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled import (
                compute_kubernetes_node_pool_disk_encryption_enabled,
            )

            check = compute_kubernetes_node_pool_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_node_pool_disk_encryption_enabled(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = [
            LKECluster(
                id=500,
                label="test-cluster",
                region="us-east",
                k8s_version="1.30",
                node_pools=[
                    LKENodePool(
                        id=10,
                        cluster_id=500,
                        node_count=3,
                        disk_encryption="enabled",
                        autoscaler_enabled=False,
                        tags=[],
                    )
                ],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled import (
                compute_kubernetes_node_pool_disk_encryption_enabled,
            )

            check = compute_kubernetes_node_pool_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "10"
            assert result[0].resource_name == "test-cluster/pool-10"

    def test_node_pool_disk_encryption_disabled(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = [
            LKECluster(
                id=500,
                label="test-cluster",
                region="us-east",
                k8s_version="1.30",
                node_pools=[
                    LKENodePool(
                        id=11,
                        cluster_id=500,
                        node_count=3,
                        disk_encryption="disabled",
                        autoscaler_enabled=False,
                        tags=[],
                    )
                ],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_node_pool_disk_encryption_enabled.compute_kubernetes_node_pool_disk_encryption_enabled import (
                compute_kubernetes_node_pool_disk_encryption_enabled,
            )

            check = compute_kubernetes_node_pool_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
