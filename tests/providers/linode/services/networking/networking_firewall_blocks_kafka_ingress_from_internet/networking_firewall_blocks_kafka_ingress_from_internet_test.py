from unittest import mock

from prowler.providers.linode.services.networking.networking_service import (
    Firewall,
    FirewallRule,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_networking_firewall_blocks_kafka_ingress_from_internet:
    def test_no_resources(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet import (
                networking_firewall_blocks_kafka_ingress_from_internet,
            )

            check = networking_firewall_blocks_kafka_ingress_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_kafka_port_blocked(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
            Firewall(
                id=100,
                label="secure-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="9092",
                        addresses_ipv4=["192.168.1.0/24"],
                        addresses_ipv6=[],
                        action="DROP",
                        label="block-port",
                    )
                ],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=1,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet import (
                networking_firewall_blocks_kafka_ingress_from_internet,
            )

            check = networking_firewall_blocks_kafka_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "secure-fw"

    def test_kafka_port_open_to_internet(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
            Firewall(
                id=101,
                label="insecure-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="9092",
                        addresses_ipv4=["0.0.0.0/0"],
                        addresses_ipv6=[],
                        action="ACCEPT",
                        label="allow-port",
                    )
                ],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=1,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_blocks_kafka_ingress_from_internet.networking_firewall_blocks_kafka_ingress_from_internet import (
                networking_firewall_blocks_kafka_ingress_from_internet,
            )

            check = networking_firewall_blocks_kafka_ingress_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
