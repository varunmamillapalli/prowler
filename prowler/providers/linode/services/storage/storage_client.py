from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.storage.storage_service import StorageService

storage_client = StorageService(Provider.get_global_provider())
