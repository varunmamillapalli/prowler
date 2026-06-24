from unittest.mock import MagicMock, patch

from linode_api4.errors import ApiError

from prowler.providers.linode.services.databases.databases_service import (
    DatabasesService,
)


def _mock_database(
    id=1,
    label="my-db",
    engine="mysql/8.0",
    region="us-east",
    status="active",
    encrypted=True,
    ssl_connection=True,
    allow_list=None,
    cluster_size=3,
    updates=None,
    tags=None,
):
    db = MagicMock()
    db.id = id
    db.label = label
    db.engine = engine
    region_mock = MagicMock()
    region_mock.id = region
    db.region = region_mock
    db.status = status
    db.encrypted = encrypted
    db.ssl_connection = ssl_connection
    db.allow_list = allow_list or []
    db.cluster_size = cluster_size
    db.updates = updates
    db.tags = tags or []
    return db


def _mock_updates(day_of_week=1, duration=3, frequency="weekly", hour_of_day=2):
    upd = MagicMock()
    upd.day_of_week = day_of_week
    upd.duration = duration
    upd.frequency = frequency
    upd.hour_of_day = hour_of_day
    upd.pending = []
    return upd


def _build_service(db_instances_return=None, db_instances_side_effect=None):
    """Build a DatabasesService with an isolated mock client."""
    service = object.__new__(DatabasesService)
    service.databases = []

    instances_callable = MagicMock()
    if db_instances_side_effect:
        instances_callable.side_effect = db_instances_side_effect
    else:
        instances_callable.return_value = db_instances_return or []

    database_mock = MagicMock()
    database_mock.instances = instances_callable

    client_mock = MagicMock()
    client_mock.database = database_mock
    service.client = client_mock
    return service


class TestLinodeDatabasesService:
    def test_describe_databases_parses_correctly(self):
        mock_dbs = [
            _mock_database(
                id=1,
                label="prod-db",
                engine="mysql/8.0",
                region="us-east",
                encrypted=True,
                ssl_connection=True,
                allow_list=["10.0.0.0/8"],
                cluster_size=3,
                updates=_mock_updates(),
            ),
        ]

        service = _build_service(db_instances_return=mock_dbs)
        service._describe_databases()

        assert len(service.databases) == 1
        db = service.databases[0]
        assert db.label == "prod-db"
        assert db.engine == "mysql/8.0"
        assert db.region == "us-east"
        assert db.encrypted is True
        assert db.ssl_connection is True
        assert db.allow_list == ["10.0.0.0/8"]
        assert db.cluster_size == 3
        assert db.updates is not None
        assert db.updates.frequency == "weekly"

    def test_describe_databases_handles_empty_list(self):
        service = _build_service(db_instances_return=[])
        service._describe_databases()

        assert len(service.databases) == 0

    def test_describe_databases_handles_api_error(self):
        service = _build_service(db_instances_side_effect=Exception("API error"))
        service._describe_databases()

        assert len(service.databases) == 0

    def test_describe_databases_missing_scope(self):
        error = ApiError(
            "Your OAuth token is not authorized to use this endpoint.",
            status=401,
        )
        service = _build_service(db_instances_side_effect=error)

        with patch(
            "prowler.providers.linode.lib.service.service.logger"
        ) as logger_mock:
            service._describe_databases()

        assert len(service.databases) == 0
        logged = " ".join(str(c) for c in logger_mock.error.call_args_list)
        assert "LinodeMissingPermissionError" in logged
        assert "databases:read_only" in logged

    def test_describe_databases_no_updates(self):
        mock_dbs = [
            _mock_database(id=1, label="no-updates-db", updates=None),
        ]

        service = _build_service(db_instances_return=mock_dbs)
        service._describe_databases()

        assert len(service.databases) == 1
        assert service.databases[0].updates is None
