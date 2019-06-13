import re

from django.contrib.auth.backends import ModelBackend

from users.models import User


def get_user_by_account(account):
    """
    根据account查询用户
    :return:
    """
    try:
        if re.match('^1[3-9]\d{9}$', account):
            # 手机号登录
            user = User.objects.get(mobile=account)
        else:
            # 用户名登录
            user = User.objects.get(username=account)
    except User.DoesNotExist:
        return None

    else:
        return user


class UsernameMobileAuthBackend(ModelBackend):
    """自定义用户认证后端"""
    def authenticate(self,request,username=None, password=None, **kwargs):
        """
        重写认证方法,实现用户名和mobile的登录
        :param request: 请求对象
        :param username: 用户名
        :param password: 密码
        :param kwargs: 其他参数
        :return:
        """
        # 自定义一个验证用户是否存在的函数
        user = get_user_by_account(username)

        if user and user.check_password(password):
            return user

