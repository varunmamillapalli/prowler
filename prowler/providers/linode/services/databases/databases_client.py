from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.databases.databases_service import (
    DatabasesService,
)

databases_client = DatabasesService(Provider.get_global_provider())
