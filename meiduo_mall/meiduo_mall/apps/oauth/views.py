import re

from QQLoginTool.QQtool import OAuthQQ
from django import http
from django.conf import settings
from django.contrib.auth import login
from django.db import DatabaseError
from django.shortcuts import render, redirect
from django_redis import get_redis_connection
# Create your views here.
from django.urls import reverse
from django.views import View

from meiduo_mall.utils.response_code import RETCODE
import logging

from oauth.models import OAuthQQUser
from oauth.utils import generate_access_token, check_access_token
from users.models import User

logger = logging.getLogger('django')


class QQUserView(View):
    """用户扫码登录的回调处理"""

    def get(self, request):
        """Oauth2.0认证"""
        # 接收Authorization Code
        code = request.GET.get('code')
        if not code:
            return http.HttpResponseForbidden('缺少必传参数')
        # 创建工具对象
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI)
        try:
            # 携带code向qq服务器请求access_token
            access_token = oauth.get_access_token(code)
            # 携带access_token去请求openid
            openid = oauth.get_open_id(access_token)
        except Exception as e:
            logger.error(e)
            return http.HttpResponseForbidden('OAuth2.0认证失败')

        # 使用openID去判断用户是否存在
        try:
            oauth_user = OAuthQQUser.objects.get(openid=openid)
        except OAuthQQUser.DoesNotExist:
            # 用户不存在
            access_token = generate_access_token(openid)
            # 拿到access_token，渲染到模板中返回
            context = {'access_token': access_token}
            return render(request, 'oauth_callback.html', context)
            pass
        else:
            # 用户存在
            # 根据外键，获取对应的QQ用户
            user = oauth_user.user

            # 实现状态保持
            login(request, user)

            # 创建重定向到首页
            response = redirect(reverse('contents:index'))

            # 写入cookie,15天
            response.set_cookie('username', user.username, max_age=3600*24*15)

            # 返回响应
            return response

    def post(self,request):
        # 接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        sms_code_cli = request.POST.get('sms_code')
        access_token = request.POST.get('access_token')

        # 检验参数
        if not all([mobile, password, sms_code_cli]):
            return http.HttpResponseForbidden("缺少必传参数")

        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('手机号格式不匹配')
        # 判断密码是否合格
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断短信验证码是否合格
        # 链接redis
        redis_connection = get_redis_connection('verify_code')
        # 从redis中获取sms_code的值
        sms_code_server = redis_connection.get('sms_code_%s' % mobile)
        # 取不取的出来值
        # 取不出
        if sms_code_server is None:
            return render(request, 'oauth_callback.html', {'sms_code_errmsg':'无效的短信验证码'})
        # 取得出
        # 判断短信验证码是否一致
        if sms_code_server.decode() != sms_code_cli:
            return render(request, 'oauth_callback.html', {'sms_code_errmsg': '输入短信验证码有误'})

        # 判断access_token 是否正确
        openid = check_access_token(access_token)
        if openid is None:
            return render(request, 'oauth_callback.html', {'openid_errmsg': '无效的openid'})

        # 保存注册数据
        try:
            user= User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 用户不存在，新建用户
            user = User.objects.create_user(username=mobile, password=password, mobile=mobile)
        else:
            # 如果用户存在，检查用户密码
            if not user.check_password(password):
                return render(request, 'oauth_callback.html', {'account_errmsg': '用户名或密码错误'})

        # 将用户绑定 openid
        try:
            OAuthQQUser.objects.create(openid=openid, user=user)
        except DatabaseError:
            return render(request, 'oauth_callback.html', {'qq_login_errmsg': 'QQ登录失败'})
        # 实现状态保持
        login(request, user)

        # 响应绑定结果
        next = request.GET.get('state')
        response = redirect(next)

        # 登录时用户名写入到 cookie，有效期15天
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        # 响应
        return response


class QQURLView(View):
    """提供QQ登录页面网址
     https://graph.qq.com/oauth2.0/authorize?
    response_type=code&
    client_id=xxx&
    redirect_uri=xxx&
    state=xxx
    """

    def get(self, request):
        # next 表示从哪个页面进入到的登录页面
        next = request.GET.get('next')

        # 获取QQ的登录页面网址
        # 创建OAuthQQ 类的对象
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI,
                        state=next)
        # 调用对象的获取QQ地址的方法
        login_url = oauth.get_qq_url()

        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'OK',
            'login_url': login_url
        })
