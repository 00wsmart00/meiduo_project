import random

from django import http
from django.shortcuts import render

# Create your views here.
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.libs.captcha.captcha import captcha
from meiduo_mall.libs.yuntongxun.ccp_sms import CCP
from meiduo_mall.utils.response_code import RETCODE
import logging

logger = logging.getLogger('django')


class SMSCodeView(View):
    """短信验证码"""

    def get(self, request, mobile):
        """

        :param request: 请求对象
        :param mobile: 手机号
        :return: Json
        """
        # 1.接受参数
        image_code_client = request.GET.get('image_code')
        uuid = request.GET.get('image_code_id')

        # 2.校验参数
        if not all([image_code_client, uuid]):
            return http.JsonResponse({
                'code': RETCODE.NECESSARYPARAMERR,
                'errmsg': '缺少必传参数'
            })
        # 3.创建连接到redis的对象
        redis_connection = get_redis_connection('verify_code')
        send_flag = redis_connection.get('send_flag_%s' % mobile)
        if send_flag:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR,
                                      'errmsg': '发送短信过于频繁'})

        # 4.提取图形验证码
        image_code_server = redis_connection.get('img_%s' % uuid)
        if image_code_server is None:
            return http.JsonResponse({
                'code': RETCODE.IMAGECODEERR,
                'errmsg': '图形验证码失效'
            })
        # 5.删除图形验证码
        try:
            redis_connection.delete('img_%s' % uuid)
        except Exception as e:
            logger.error(e)
        # 6.对比图形验证码
        # bytes转成字符串
        image_code_server = image_code_server.decode()

        # 转成小写字母后比较
        if image_code_server.lower() != image_code_client.lower():
            return http.JsonResponse({
                'code': RETCODE.IMAGECODEERR,
                'errmsg': '输入图形验证码错误'
            })
        # 7.生成短信验证码,6位数
        sms_code = '%06d' % random.randint(0, 999999)
        logger.info(sms_code)

        # 创建一个Redis管道
        pl =redis_connection.pipeline()

        # 8.保存验证码
        pl.setex('sms_code_%s' % mobile, 300, sms_code)
        # 保存验证码的时候打一个标记
        pl.setex('send_flag_%s' % mobile, 60, 1)

        # 执行管道的请求
        pl.execute()
        # 9.发送验证码
        # 短信模板
        from celery_tasks.sms_code.tasks import send_sms_code
        send_sms_code.delay(mobile, sms_code)

        # 10.响应结果
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': '发送短信成功'
        })


class ImageCodeView(View):
    """图形验证码"""

    def get(self, request, uuid):
        """

        :param request: 请求对象
        :param uuid: 当前用户的唯一id
        :return: image/jpg
        """
        # 生成图片验证码
        text, image = captcha.generate_captcha()

        # 保存图片验证码
        redis_connection = get_redis_connection('verify_code')

        # 图形验证码有效期,单位:秒
        redis_connection.setex('img_%s' % uuid, 300, text)

        # 响应图形验证码
        return http.HttpResponse(image, content_type='image/jpg')
