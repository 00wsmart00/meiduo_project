import re

from django import http
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required

from meiduo_mall.utils.response_code import RETCODE
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

    def authenticate(self, request, username=None, password=None, **kwargs):
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


class LoginRequired(object):
    """验证用户是否登陆的工具类"""

    # 重写该函数:
    @classmethod
    def as_view(cls, **initkwargs):
        # 调用父类的 as_view() 方法
        view = super().as_view()
        # 添加装饰行为:
        return login_required(view)

# 自定义返回Json的login_required装饰器


from django.utils.decorators import wraps


def login_required_json(view_func):
    """
    判断用户是否登录的装饰器，返回json
    :param view_func:被装饰的视图函数
    :return:json、view_func
    """
    @wraps(view_func)
    def wrapper(request,*args,**kwargs):
        # 如果主用户没有登录，返回json数据
        if not request.user.is_authenticated():
            return http.JsonResponse({
                'code':RETCODE.SESSIONERR,
                'errmsg':'用户登录'
            })
        else:
            # 登录的话，进入到view_func中，
            return view_func(request,*args,**kwargs)

    return wrapper


class LoginRequiredJSONMixin(object):
    """验证用户是否登录并返回json的扩展类"""
    @classmethod
    def as_view(cls):
        view = super().as_view()
        return login_required_json(view)



