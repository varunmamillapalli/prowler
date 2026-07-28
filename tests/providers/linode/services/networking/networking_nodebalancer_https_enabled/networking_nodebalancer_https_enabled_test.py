from unittest import mock

from prowler.providers.linode.services.networking.networking_service import (
    NodeBalancer,
    NodeBalancerConfig,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_networking_nodebalancer_https_enabled:
    def test_no_resources(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled import (
                networking_nodebalancer_https_enabled,
            )

            check = networking_nodebalancer_https_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_nodebalancer_https_enabled(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = [
            NodeBalancer(
                id=200,
                label="secure-nb",
                region="us-east",
                status="running",
                configs=[
                    NodeBalancerConfig(
                        id=1,
                        port=443 if "https" != "http" else 80,
                        protocol="https",
                        algorithm="roundrobin",
                        stickiness="none",
                        check="none",
                        cipher_suite="recommended",
                        proxy_protocol="none",
                        ssl_commonname="example.com",
                        ssl_fingerprint="AA:BB:CC",
                    )
                ],
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
                "prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled import (
                networking_nodebalancer_https_enabled,
            )

            check = networking_nodebalancer_https_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "200"
            assert result[0].resource_name == "secure-nb"

    def test_nodebalancer_http_only(self):
        networking_client = mock.MagicMock()
        networking_client.nodebalancers = [
            NodeBalancer(
                id=201,
                label="insecure-nb",
                region="us-east",
                status="running",
                configs=[
                    NodeBalancerConfig(
                        id=1,
                        port=443 if "http" != "http" else 80,
                        protocol="http",
                        algorithm="roundrobin",
                        stickiness="none",
                        check="none",
                        cipher_suite="legacy",
                        proxy_protocol="none",
                        ssl_commonname="",
                        ssl_fingerprint="",
                    )
                ],
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
                "prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_nodebalancer_https_enabled.networking_nodebalancer_https_enabled import (
                networking_nodebalancer_https_enabled,
            )

            check = networking_nodebalancer_https_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
