import os

from celery import Celery
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "meiduo_mall.settings.dev")
# 创建celery实例

celery_apps = Celery('meiduo')

celery_apps.config_from_object('celery_tasks.config')

celery_apps.autodiscover_tasks(['celery_tasks.sms_code', 'celery_tasks.email'])

