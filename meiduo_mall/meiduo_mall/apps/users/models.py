from django.contrib.auth.models import AbstractUser
from django.db import models
from itsdangerous import TimedJSONWebSignatureSerializer,BadData
from django.conf import settings
# Create your models here.
from meiduo_mall.utils.models import BaseModel


class User(AbstractUser):
    """自定义用户模型"""

    # 在用户模型的基础上增加mobile字段
    mobile = models.CharField(max_length=11, unique=True)
    # 新增 email_active 字段
    # 用于记录邮箱是否激活, 默认为 False: 未激活
    email_active = models.BooleanField(default=False, verbose_name='邮箱验证状态')
    # 新增
    default_address = models.ForeignKey('Address',
                                        related_name='users',
                                        null=True,
                                        blank=True,
                                        on_delete=models.SET_NULL,
                                        verbose_name='默认地址')

    # 对当前的表进行相关设置
    class Meta:
        db_table = 'tb_users'
        verbose_name = '用户'
        verbose_name_plural = verbose_name

    # 在str魔法方法中，返回用户名称
    def __str__(self):
        return self.username

    def generate_verify_email_url(self):
        """
        生成邮箱验证链接
        :return: verify_url
        """
        # 1.调用itdangerous中生成的类，生成对象
        serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                     expires_in=60 * 60 * 24)
        # 2.拼接参数
        data = {'user_id':self.id,'email':self.email}

        # 3.生成token值，这个值是byte，所以解码
        token = serializer.dumps(data).decode()

        # 4.拼接url
        verify_url = settings.EMAIL_VERIFY_URL + '?token=' + token

        # 5.返回
        return verify_url

    @staticmethod
    def check_email_token(token):
        """验证token并提取user"""
        # 1.生成解密对象
        serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                     expires_in=60 * 60 * 24)
        # 2.解密token
        try:
            data = serializer.loads(token)
        except BadData:
            return None
        # 3.从用户表中获取相应的用户
        user_id = data['user_id']
        email = data['email']
        try:
            user = User.objects.get(id=user_id,email=email)
        except User.DoesNotExist:
            return None

        return user


class Address(BaseModel):
    """
    用户地址
    """
    user = models.ForeignKey(User,
                             on_delete=models.CASCADE,
                             related_name='addresses',
                             verbose_name='用户')

    province = models.ForeignKey('areas.Area',
                                 on_delete=models.PROTECT,
                                 related_name='province_addresses',
                                 verbose_name='省')

    city = models.ForeignKey('areas.Area',
                             on_delete=models.PROTECT,
                             related_name='city_addresses',
                             verbose_name='市')

    district = models.ForeignKey('areas.Area',
                                 on_delete=models.PROTECT,
                                 related_name='district_addresses',
                                 verbose_name='区')

    title = models.CharField(max_length=20, verbose_name='地址名称')
    receiver = models.CharField(max_length=20, verbose_name='收货人')
    place = models.CharField(max_length=50, verbose_name='地址')
    mobile = models.CharField(max_length=11, verbose_name='手机')
    tel = models.CharField(max_length=20,
                           null=True,
                           blank=True,
                           default='',
                           verbose_name='固定电话')

    email = models.CharField(max_length=30,
                             null=True,
                             blank=True,
                             default='',
                             verbose_name='电子邮箱')

    is_deleted = models.BooleanField(default=False, verbose_name='逻辑删除')

    class Meta:
        db_table = 'tb_address'
        verbose_name = '用户地址'
        verbose_name_plural = verbose_name
        ordering = ['-update_time']
        

