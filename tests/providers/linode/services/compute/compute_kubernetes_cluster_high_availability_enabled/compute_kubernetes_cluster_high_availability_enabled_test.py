from unittest import mock

from prowler.providers.linode.services.compute.compute_service import (
    LKECluster,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_compute_kubernetes_cluster_high_availability_enabled:
    def test_no_resources(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled import (
                compute_kubernetes_cluster_high_availability_enabled,
            )

            check = compute_kubernetes_cluster_high_availability_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_pass(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = [
            LKECluster(
                id=500,
                label="ha-cluster",
                region="us-east",
                k8s_version="1.30",
                high_availability=True,
                acl_enabled=True,
                acl_addresses_ipv4=["10.0.0.0/8"],
                acl_addresses_ipv6=[],
                node_pools=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled import (
                compute_kubernetes_cluster_high_availability_enabled,
            )

            check = compute_kubernetes_cluster_high_availability_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "500"
            assert result[0].resource_name == "ha-cluster"

    def test_fail(self):
        compute_client = mock.MagicMock()
        compute_client.lke_clusters = [
            LKECluster(
                id=501,
                label="no-ha-cluster",
                region="us-east",
                k8s_version="1.30",
                high_availability=False,
                acl_enabled=True,
                acl_addresses_ipv4=["10.0.0.0/8"],
                acl_addresses_ipv6=[],
                node_pools=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_kubernetes_cluster_high_availability_enabled.compute_kubernetes_cluster_high_availability_enabled import (
                compute_kubernetes_cluster_high_availability_enabled,
            )

            check = compute_kubernetes_cluster_high_availability_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
