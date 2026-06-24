from unittest.mock import MagicMock, patch

from linode_api4.errors import ApiError

from prowler.providers.linode.services.compute.compute_service import (
    ComputeService,
)


def _mock_instance(
    id=1,
    label="my-instance",
    region="us-east",
    status="running",
    backups_enabled=True,
    disk_encryption="enabled",
    watchdog_enabled=True,
    tags=None,
):
    inst = MagicMock()
    inst.id = id
    inst.label = label
    region_mock = MagicMock()
    region_mock.id = region
    inst.region = region_mock
    inst.status = status
    backups = MagicMock()
    backups.enabled = backups_enabled
    inst.backups = backups
    inst.disk_encryption = disk_encryption
    inst.watchdog_enabled = watchdog_enabled
    inst.tags = tags or []
    return inst


def _build_service(linode_instances_return=None, linode_instances_side_effect=None):
    """Build a ComputeService with an isolated mock client."""
    service = object.__new__(ComputeService)
    service.instances = []

    # Build isolated mock hierarchy for client.linode.instances()
    # Must explicitly create the instances callable as a fresh MagicMock
    # because check tests contaminate MagicMock class with instances=[...]
    instances_callable = MagicMock()
    if linode_instances_side_effect:
        instances_callable.side_effect = linode_instances_side_effect
    else:
        instances_callable.return_value = linode_instances_return or []

    linode_mock = MagicMock()
    linode_mock.instances = instances_callable

    client_mock = MagicMock()
    client_mock.linode = linode_mock
    service.client = client_mock
    return service


class TestLinodeComputeService:
    def test_describe_instances_parses_correctly(self):
        mock_instances = [
            _mock_instance(id=1, label="web-1", region="us-east"),
            _mock_instance(id=2, label="db-1", region="eu-west", backups_enabled=False),
        ]

        service = _build_service(linode_instances_return=mock_instances)
        service._describe_instances()

        assert len(service.instances) == 2
        assert service.instances[0].label == "web-1"
        assert service.instances[0].region == "us-east"
        assert service.instances[0].backups_enabled is True
        assert service.instances[1].label == "db-1"
        assert service.instances[1].backups_enabled is False

    def test_describe_instances_handles_empty_list(self):
        service = _build_service(linode_instances_return=[])
        service._describe_instances()

        assert len(service.instances) == 0

    def test_describe_instances_handles_api_error(self):
        service = _build_service(linode_instances_side_effect=Exception("API error"))
        service._describe_instances()

        assert len(service.instances) == 0

    def test_describe_instances_missing_scope_logs_permission_error(self):
        error = ApiError(
            "Your OAuth token is not authorized to use this endpoint.", status=401
        )
        service = _build_service(linode_instances_side_effect=error)

        with patch(
            "prowler.providers.linode.lib.service.service.logger"
        ) as logger_mock:
            service._describe_instances()

        assert len(service.instances) == 0
        logged = " ".join(str(c) for c in logger_mock.error.call_args_list)
        assert "LinodeMissingPermissionError" in logged
        assert "linodes:read_only" in logged

    def test_describe_instances_disk_encryption(self):
        mock_instances = [
            _mock_instance(id=1, disk_encryption="enabled"),
            _mock_instance(id=2, disk_encryption="disabled"),
        ]

        service = _build_service(linode_instances_return=mock_instances)
        service._describe_instances()

        assert service.instances[0].disk_encryption == "enabled"
        assert service.instances[1].disk_encryption == "disabled"

    def test_describe_instances_region_filter_keeps_only_matching(self):
        mock_instances = [
            _mock_instance(id=1, label="eu", region="eu-central"),
            _mock_instance(id=2, label="us", region="us-east"),
            _mock_instance(id=3, label="eu-2", region="eu-central"),
        ]
        service = _build_service(linode_instances_return=mock_instances)
        service.provider = MagicMock()
        service.provider.regions = {"eu-central"}

        service._describe_instances()

        assert len(service.instances) == 2
        assert {i.label for i in service.instances} == {"eu", "eu-2"}
        assert all(i.region == "eu-central" for i in service.instances)

    def test_describe_instances_no_region_filter_keeps_all(self):
        mock_instances = [
            _mock_instance(id=1, region="eu-central"),
            _mock_instance(id=2, region="us-east"),
        ]
        service = _build_service(linode_instances_return=mock_instances)
        service.provider = MagicMock()
        service.provider.regions = None

        service._describe_instances()

        assert len(service.instances) == 2


def _mock_lke_cluster(
    id=1,
    label="my-cluster",
    region="us-east",
    k8s_version="1.30",
    tier="standard",
    high_availability=False,
    acl_enabled=False,
    acl_addresses_ipv4=None,
    acl_addresses_ipv6=None,
    pools=None,
    tags=None,
):
    cluster = MagicMock()
    cluster.id = id
    cluster.label = label
    region_mock = MagicMock()
    region_mock.id = region
    cluster.region = region_mock
    kv = MagicMock()
    kv.id = k8s_version
    cluster.k8s_version = kv
    cluster.tier = tier
    cluster.tags = tags or []

    cp = MagicMock()
    cp.high_availability = high_availability
    cluster.control_plane = cp

    acl = MagicMock()
    acl.enabled = acl_enabled
    addrs = MagicMock()
    addrs.ipv4 = acl_addresses_ipv4 or []
    addrs.ipv6 = acl_addresses_ipv6 or []
    acl.addresses = addrs
    cluster.control_plane_acl = acl

    cluster.pools = pools or []
    return cluster


def _mock_node_pool(
    id=1, count=3, disk_encryption="enabled", autoscaler_enabled=False, tags=None
):
    pool = MagicMock()
    pool.id = id
    pool.count = count
    pool.disk_encryption = disk_encryption
    autoscaler = MagicMock()
    autoscaler.enabled = autoscaler_enabled
    pool.autoscaler = autoscaler
    pool.tags = tags or []
    return pool


def _build_lke_service(lke_clusters_return=None, lke_clusters_side_effect=None):
    """Build a ComputeService with a mock for client.lke.clusters()."""
    service = object.__new__(ComputeService)
    service.instances = []
    service.lke_clusters = []

    clusters_callable = MagicMock()
    if lke_clusters_side_effect:
        clusters_callable.side_effect = lke_clusters_side_effect
    else:
        clusters_callable.return_value = lke_clusters_return or []

    lke_mock = MagicMock()
    lke_mock.clusters = clusters_callable

    client_mock = MagicMock()
    client_mock.lke = lke_mock
    service.client = client_mock
    return service


class TestLinodeComputeServiceLKE:
    def test_describe_lke_clusters_parses_correctly(self):
        pools = [_mock_node_pool(id=10, count=3, disk_encryption="enabled")]
        mock_clusters = [
            _mock_lke_cluster(
                id=1,
                label="prod-cluster",
                region="us-east",
                k8s_version="1.30",
                high_availability=True,
                acl_enabled=True,
                acl_addresses_ipv4=["10.0.0.0/8"],
                pools=pools,
            ),
        ]

        service = _build_lke_service(lke_clusters_return=mock_clusters)
        service._describe_lke_clusters()

        assert len(service.lke_clusters) == 1
        cluster = service.lke_clusters[0]
        assert cluster.label == "prod-cluster"
        assert cluster.region == "us-east"
        assert cluster.k8s_version == "1.30"
        assert cluster.high_availability is True
        assert cluster.acl_enabled is True
        assert cluster.acl_addresses_ipv4 == ["10.0.0.0/8"]
        assert len(cluster.node_pools) == 1
        assert cluster.node_pools[0].disk_encryption == "enabled"

    def test_describe_lke_clusters_handles_empty_list(self):
        service = _build_lke_service(lke_clusters_return=[])
        service._describe_lke_clusters()

        assert len(service.lke_clusters) == 0

    def test_describe_lke_clusters_handles_api_error(self):
        service = _build_lke_service(lke_clusters_side_effect=Exception("API error"))
        service._describe_lke_clusters()

        assert len(service.lke_clusters) == 0

    def test_describe_lke_clusters_missing_scope(self):
        error = ApiError(
            "Your OAuth token is not authorized to use this endpoint.",
            status=401,
        )
        service = _build_lke_service(lke_clusters_side_effect=error)

        with patch(
            "prowler.providers.linode.lib.service.service.logger"
        ) as logger_mock:
            service._describe_lke_clusters()

        assert len(service.lke_clusters) == 0
        logged = " ".join(str(c) for c in logger_mock.error.call_args_list)
        assert "LinodeMissingPermissionError" in logged
        assert "lke:read_only" in logged
