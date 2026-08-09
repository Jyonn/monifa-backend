from django.db import models
from smartdjango import Code, Error


@Error.register
class ConfigErrors:
    NOT_FOUND = Error("配置不存在", code=Code.NotFound)
    CREATE = Error("配置写入失败", code=Code.InternalServerError)


class Config(models.Model):
    key = models.CharField(max_length=128, unique=True)
    value = models.CharField(max_length=4096)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    @classmethod
    def get_config_by_key(cls, key):
        try:
            return cls.objects.get(key=key)
        except cls.DoesNotExist as error:
            raise ConfigErrors.NOT_FOUND(details=error)

    @classmethod
    def get_value_by_key(cls, key, default=None):
        try:
            return cls.get_config_by_key(key).value
        except Exception:
            return default

    @classmethod
    def update_value(cls, key, value):
        try:
            config, _ = cls.objects.update_or_create(key=key, defaults={"value": str(value)})
            return config
        except Exception as error:
            raise ConfigErrors.CREATE(details=error)


class ConfigInstance:
    FRONTEND_URL = "frontend-url"

    QITIAN_APP_ID = "qt-app-id"
    QITIAN_APP_SECRET = "qt-app-secret"
    QITIAN_HOST = "qt-host"

    GITHUB_CLIENT_ID = "github-client-id"
    GITHUB_CLIENT_SECRET = "github-client-secret"


CI = ConfigInstance

