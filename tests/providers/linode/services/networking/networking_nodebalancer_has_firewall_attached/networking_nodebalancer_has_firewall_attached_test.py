from unittest import mock

from prowler.providers.linode.services.networking.networking_service import (
    NodeBalancer,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_networking_nodebalancer_has_firewall_attached:
    def test_no_resources(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached import (
                networking_nodebalancer_has_firewall_attached,
            )

            check = networking_nodebalancer_has_firewall_attached()
            result = check.execute()

            assert len(result) == 0

    def test_pass(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = [
            NodeBalancer(
                id=200,
                label="secure-nb",
                region="us-east",
                status="running",
                configs=[],
                has_firewall=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached import (
                networking_nodebalancer_has_firewall_attached,
            )

            check = networking_nodebalancer_has_firewall_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "200"
            assert result[0].resource_name == "secure-nb"

    def test_fail(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = [
            NodeBalancer(
                id=201,
                label="insecure-nb",
                region="us-east",
                status="running",
                configs=[],
                has_firewall=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_has_firewall_attached.networking_nodebalancer_has_firewall_attached import (
                networking_nodebalancer_has_firewall_attached,
            )

            check = networking_nodebalancer_has_firewall_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
