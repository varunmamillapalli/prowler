from unittest.mock import MagicMock, patch

from linode_api4.errors import ApiError

from prowler.providers.linode.services.storage.storage_service import (
    StorageService,
)


def _mock_volume(
    id=1,
    label="my-vol",
    region="us-east",
    status="active",
    size=50,
    linode_id=1,
    encryption="enabled",
    tags=None,
):
    vol = MagicMock()
    vol.id = id
    vol.label = label
    region_mock = MagicMock()
    region_mock.id = region
    vol.region = region_mock
    vol.status = status
    vol.size = size
    vol.linode_id = linode_id
    vol.encryption = encryption
    vol.tags = tags or []
    return vol


def _mock_bucket(
    label="my-bucket",
    region="us-east-1",
    hostname="my-bucket.us-east-1.linodeobjects.com",
    objects=10,
    size=1024,
    endpoint_type="E0",
    acl="private",
    cors_enabled=False,
):
    bucket = MagicMock()
    bucket.label = label
    bucket.region = region
    bucket.hostname = hostname
    bucket.objects = objects
    bucket.size = size
    bucket.endpoint_type = endpoint_type
    access = MagicMock()
    access.acl = acl
    access.cors_enabled = cors_enabled
    bucket.access_get.return_value = access
    return bucket


def _mock_key(id=1, label="my-key", limited=True, regions=None, bucket_access=None):
    key = MagicMock()
    key.id = id
    key.label = label
    key.limited = limited
    key.regions = regions or []
    key.bucket_access = bucket_access or []
    return key


def _build_volume_service(volumes_return=None, volumes_side_effect=None):
    service = object.__new__(StorageService)
    service.volumes = []
    service.object_buckets = []
    service.object_keys = []

    volumes_callable = MagicMock()
    if volumes_side_effect:
        volumes_callable.side_effect = volumes_side_effect
    else:
        volumes_callable.return_value = volumes_return or []

    client_mock = MagicMock()
    client_mock.volumes = volumes_callable
    service.client = client_mock
    return service


def _build_bucket_service(buckets_return=None, buckets_side_effect=None):
    service = object.__new__(StorageService)
    service.volumes = []
    service.object_buckets = []
    service.object_keys = []

    buckets_callable = MagicMock()
    if buckets_side_effect:
        buckets_callable.side_effect = buckets_side_effect
    else:
        buckets_callable.return_value = buckets_return or []

    obj_storage = MagicMock()
    obj_storage.buckets = buckets_callable

    client_mock = MagicMock()
    client_mock.object_storage = obj_storage
    service.client = client_mock
    return service


def _build_key_service(keys_return=None, keys_side_effect=None):
    service = object.__new__(StorageService)
    service.volumes = []
    service.object_buckets = []
    service.object_keys = []

    keys_callable = MagicMock()
    if keys_side_effect:
        keys_callable.side_effect = keys_side_effect
    else:
        keys_callable.return_value = keys_return or []

    obj_storage = MagicMock()
    obj_storage.keys = keys_callable

    client_mock = MagicMock()
    client_mock.object_storage = obj_storage
    service.client = client_mock
    return service


class TestLinodeStorageServiceVolumes:
    def test_describe_volumes_parses_correctly(self):
        mock_vols = [
            _mock_volume(id=1, label="vol-1", region="us-east", encryption="enabled"),
            _mock_volume(id=2, label="vol-2", region="eu-west", encryption="disabled"),
        ]

        service = _build_volume_service(volumes_return=mock_vols)
        service._describe_volumes()

        assert len(service.volumes) == 2
        assert service.volumes[0].label == "vol-1"
        assert service.volumes[0].encryption == "enabled"
        assert service.volumes[1].encryption == "disabled"

    def test_describe_volumes_handles_empty_list(self):
        service = _build_volume_service(volumes_return=[])
        service._describe_volumes()

        assert len(service.volumes) == 0

    def test_describe_volumes_handles_api_error(self):
        service = _build_volume_service(volumes_side_effect=Exception("API error"))
        service._describe_volumes()

        assert len(service.volumes) == 0

    def test_describe_volumes_missing_scope(self):
        error = ApiError(
            "Your OAuth token is not authorized to use this endpoint.",
            status=401,
        )
        service = _build_volume_service(volumes_side_effect=error)

        with patch(
            "prowler.providers.linode.lib.service.service.logger"
        ) as logger_mock:
            service._describe_volumes()

        assert len(service.volumes) == 0
        logged = " ".join(str(c) for c in logger_mock.error.call_args_list)
        assert "LinodeMissingPermissionError" in logged
        assert "volumes:read_only" in logged


class TestLinodeStorageServiceBuckets:
    def test_describe_object_buckets_parses_correctly(self):
        mock_buckets = [
            _mock_bucket(label="b1", acl="private", cors_enabled=False),
        ]

        service = _build_bucket_service(buckets_return=mock_buckets)
        service._describe_object_buckets()

        assert len(service.object_buckets) == 1
        assert service.object_buckets[0].label == "b1"
        assert service.object_buckets[0].acl == "private"
        assert service.object_buckets[0].cors_enabled is False

    def test_describe_object_buckets_handles_empty_list(self):
        service = _build_bucket_service(buckets_return=[])
        service._describe_object_buckets()

        assert len(service.object_buckets) == 0

    def test_describe_object_buckets_handles_api_error(self):
        service = _build_bucket_service(buckets_side_effect=Exception("API error"))
        service._describe_object_buckets()

        assert len(service.object_buckets) == 0


class TestLinodeStorageServiceKeys:
    def test_describe_object_keys_parses_correctly(self):
        mock_keys = [
            _mock_key(id=1, label="key-1", limited=True),
        ]

        service = _build_key_service(keys_return=mock_keys)
        service._describe_object_keys()

        assert len(service.object_keys) == 1
        assert service.object_keys[0].label == "key-1"
        assert service.object_keys[0].limited is True

    def test_describe_object_keys_handles_empty_list(self):
        service = _build_key_service(keys_return=[])
        service._describe_object_keys()

        assert len(service.object_keys) == 0

    def test_describe_object_keys_handles_api_error(self):
        service = _build_key_service(keys_side_effect=Exception("API error"))
        service._describe_object_keys()

        assert len(service.object_keys) == 0
