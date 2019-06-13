from celery_tasks.main import celery_apps
from celery_tasks.yuntongxun.ccp_sms import CCP


@celery_apps.task(bind=True, name='send_sms_code', retry_backoff=3)
def send_sms_code(self, mobile, sms_code):
    """
    使用celery给我们发送短信
    :param self:
    :param mobile:
    :param sms_code:
    :return:
    """
    try:
        result = CCP().send_template_sms(mobile, [sms_code, 5], 1)
    except Exception as e:
        raise self.retry(exc=e, max_retries=3)

    if result != 0:
        # 发送失败
        raise self.retry(exc=Exception('发送失败'), max_retries=3)

    return result
