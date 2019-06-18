import json
import re

from django import http
from django.contrib.auth import login, authenticate, logout
from django.db import DatabaseError
from django.shortcuts import render, redirect
# Create your views here.
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.utils.response_code import RETCODE
from users.models import User, Address
from users.utils import LoginRequired, LoginRequiredJSONMixin
import logging

logger = logging.getLogger('django')


class ChangePasswordView(LoginRequired,View):
    def get(self,request):
        """展示修改密码界面"""
        return render(request,'user_center_pass.html')

    def post(self,request):
        """实现修改密码逻辑"""
        # 1.接收参数
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')
        # 2.校验参数
        if not all([old_password,new_password,new_password2]):
            return http.HttpResponseForbidden('缺少必传参数')
        try:
            request.user.check_password(old_password)
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_pass.html', {'origin_pwd_errmsg':'原始密码错误'})
        if not re.match(r'^[0-9A-Za-z]{8,20}$', new_password):
            return http.HttpResponseForbidden('密码最少8位，最长20位')
        if new_password != new_password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')

        # 3.修改密码
        try:
            request.user.set_password(new_password)
            request.user.save()
        except Exception as e:
            logger.error(e)
            return render(request,'user_center_pass.html',  {'change_pwd_errmsg': '修改密码失败'})
        # 4.清理状态保持信息
        logout(request)
        response = redirect(reverse('users:login'))
        response.delete_cookie('username')
        # 5.响应密码修改结果,重定向到登录界
        return response


class UpdateTitleAddressView(LoginRequiredJSONMixin,View):
    """设置地址标题"""
    def put(self,request,address_id):
        # 1.接收参数,地址标题
        json_dict = json.loads(request.body.decode())
        title = json_dict.get('title')
        try:
            # 2.查询地址
            address = Address.objects.get(id=address_id)

            # 3.设置新的地址
            address.title = title
            address.save()
        except Exception as e:
            http.JsonResponse({
                'code':RETCODE.DBERR,
                'errmsg':'设置地址标题失败'
            })
        # 4.响应
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': '设置地址标题成功'
        })


class DefaultAddressView(LoginRequiredJSONMixin,View):
    """设置默认地址"""
    def put(self,request,address_id):
        try:
            # 1.接收参数
            address = Address.objects.get(id=address_id)
            # 2.设置地址为默认地址
            request.user.default_address = address
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({
                'code':RETCODE.DBERR,
                'errmsg': '设置默认地址失败'
            })
        # 3.响应设置默认地址结果
        return http.JsonResponse({
            'code':RETCODE.OK,
            'errmsg': 'ok'
        })


class UpdateDestroyAddressView(LoginRequiredJSONMixin, View):
    """修改和删除地址"""

    def put(self, request, address_id):
        """修改地址"""
        # 1.接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        # 2.校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')
        # 3.判断地址是否存在,并更新地址信息
        try:
            Address.objects.filter(id=address_id).update(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email
            )
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({
                'code': RETCODE.DBERR,
                'errmsg': '更新地址失败'
            })

        # 4.构造响应数据
        address = Address.objects.get(id=address_id)
        address_dict = {
            "id": address.id,
            "title": address.title,
            "receiver": address.receiver,
            "province": address.province.name,
            "city": address.city.name,
            "district": address.district.name,
            "place": address.place,
            "mobile": address.mobile,
            "tel": address.tel,
            "email": address.email
        }
        # 5.响应更新地址结果
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': '更新地址成功',
            'address': address_dict
        })

    def delete(self, request, address_id):
        """删除地址"""
        try:
            # 1.查询要删除的地址
            address = Address.objects.get(id=address_id)

            # 2.将地址逻辑删除设置为True
            address.is_deleted = True
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({
                'code': RETCODE.OK,
                'errmsg': '删除地址失败'

            })
        # 3.响应删除地址结果
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': '删除地址成功'
        })


class CreateAddressView(LoginRequiredJSONMixin, View):
    """新增地址"""

    def post(self, request):
        """实现新增地址逻辑"""
        # 1.获取地址个数
        count = request.user.addresses.filter(is_deleted=False).count()

        # 2.判断是否超过地址上限,最多20个
        if count >= 20:
            # RETCODE.THROTTLINGERR:  4002
            return http.JsonResponse({
                'code': RETCODE.THROTTLINGERR,
                'errmsg': '超过地址上限'
            })
        # 3.接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        # 4.校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')
        # 5.保存地址信息
        try:
            address = Address.objects.create(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email
            )
            # 6.设置默认地址
            if not request.user.default_address:
                request.user.default_address = address
                request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({
                'code': RETCODE.DBERR, 'errmsg': '新增地址失败'
            })

        # 7.新增地址成功,将新增的地址响应给前端实现局部刷新
        address_dict = {
            "id": address.id,
            "title": address.title,
            "receiver": address.receiver,
            "province": address.province.name,
            "city": address.city.name,
            "district": address.district.name,
            "place": address.place,
            "mobile": address.mobile,
            "tel": address.tel,
            "email": address.email
        }
        # 8.响应保存结果
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': '新增地址成功',
            'address': address_dict

        })


class AddressView(LoginRequired, View):
    """用户收货地址展示"""

    def get(self, request):
        """提供地址管理界面
        """
        # 获取所有的地址:
        addresses = Address.objects.filter(user=request.user, is_deleted=False)

        # 创建空的列表
        address_dict_list = []
        # 遍历
        for address in addresses:
            address_dict = {
                "id": address.id,
                "title": address.title,
                "receiver": address.receiver,
                "province": address.province.name,
                "city": address.city.name,
                "district": address.district.name,
                "place": address.place,
                "mobile": address.mobile,
                "tel": address.tel,
                "email": address.email
            }

            # 将默认地址移动到最前面
            default_address = request.user.default_address
            if default_address.id == address.id:
                # 查询集 addresses 没有 insert 方法
                address_dict_list.insert(0, address_dict)
            else:
                address_dict_list.append(address_dict)

        context = {
            'default_address_id': request.user.default_address_id,
            'addresses': address_dict_list,
        }

        return render(request, 'user_center_site.html', context)


class VerifyEmailView(View):
    """验证邮箱"""

    def get(self, request):
        # 1.接受参数
        token = request.GET.get('token')
        # 2.校验参数
        if not token:
            return http.HttpResponseForbidden('缺少必传参数')
        # 4.解密token
        user = User.check_email_token(token)
        # 5.验证user
        if not user:
            return http.HttpResponseForbidden('无效的token')
        # 6.更新邮箱验证状态字段email_active
        try:
            user.email_active = True
            user.save()
        except Exception as e:
            logger.error(e)
            return http.HttpResponseForbidden('激活邮件失败')
        # 7.返回
        return redirect(reverse('users:info'))


class EmailView(LoginRequiredJSONMixin, View):
    """添加邮箱"""

    def put(self, request):
        """实现添加邮箱的逻辑"""
        # 1.接受参数
        json_dict = json.loads(request.body.decode())
        email = json_dict.get('email')
        # 2.校验参数
        if not email:
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('参数email有误')
        # 3.更新
        try:
            request.user.email = email
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({
                'code': RETCODE.DBERR,
                'errmsg': '添加邮箱失败'
            })
        # 发送邮件
        from celery_tasks.email.tasks import send_verify_email
        # 异步发送电子邮件
        verify_url = request.user.generate_verify_email_url()
        send_verify_email.delay(email, verify_url)
        # 4.响应
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok'
        })


class UserInfoView(LoginRequired, View):
    """用户中心"""

    def get(self, request):
        """提供个人中心界面"""

        context = {
            'username': request.user.username,
            'mobile': request.user.mobile,
            'email': request.user.email,
            'email_active': request.user.email_active
        }
        return render(request, 'user_center_info.html', context=context)


class LogoutView(View):
    """退出登录"""

    def get(self, request):
        """实现退出的逻辑"""

        # 清理session
        logout(request)

        # 退出登录后重定向到首页
        response = redirect(reverse('contents:index'))

        # 退出登录时清理Cookie中的username
        response.delete_cookie('username')

        # 返回响应
        return response


class LoginView(View):
    """用户名登陆"""

    def get(self, request):
        """提供登陆界面"""

        return render(request, 'login.html')

    def post(self, request):
        """实现登陆逻辑"""
        # 1.获取前端传递参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        # 2.校验参数
        # 整体
        if not all([username, password]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 单个
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入正确的用户名或手机号')
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('密码最少8位,最长20位')

        # 3.获取登陆用户,并查看是否存在
        user = authenticate(username=username, password=password)
        if user is None:
            return render(request, 'login.html', {'account_errmsg': '用户名或密码错误'})

        # 4.实现状态保持
        login(request, user)
        # 设置状态保持的周期
        if remembered != 'on':
            # 不记住用户,浏览器会话结束后就过期
            request.session.set_expiry(0)
        else:
            # 记住用户,两周后过期
            request.session.set_expiry(None)
        next = request.GET.get('next')
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('contents:index'))
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        # 5.返回响应
        return response


class MobileCountView(View):
    """判断手机号是否被注册"""

    def get(self, request, mobile):
        """

        :param request:
        :return: Json
        """
        # 数据库去查询
        count = User.objects.filter(mobile=mobile).count()

        # 返回
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok',
            'count': count
        })


class UsernameCountView(View):
    """判断用户名是否重复注册"""

    def get(self, request, username):
        """

        :param request:
        :return: Json
        """
        # 获取参数
        # 数据库去查询
        count = User.objects.filter(username=username).count()

        # 返回
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok',
            'count': count
        })


class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """
        提供注册页面
        :param request: 请求对象
        :return: 注册界面
        """
        return render(request, 'register.html')

    def post(self, request):
        """提交注册页面"""
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')
        allow = request.POST.get('allow')
        sms_code_client = request.POST.get('sms_code')

        # 判断参数是否齐全
        if not all([username, password, password2, mobile, allow, sms_code_client]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')
        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        # 判断是否勾选用户协议
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')

        # 获取redis链接对象
        redis_connection = get_redis_connection('verify_code')

        # 从redis中获取保存的sms_code
        sms_code_server = redis_connection.get('sms_code_%s' % mobile)

        # 判断sms_code_server是否存在
        if sms_code_server is None:
            # 不存在直接返回, 说明服务器的过期了, 超时
            return render(request,
                          'register.html',
                          {'sms_code_errmsg': '无效的短信验证码'})
        # 如果存在,对比两者
        if sms_code_client != sms_code_server.decode():
            # 对比失败, 说明短信验证码有问题, 直接返回:
            return render(request,
                          'register.html',
                          {'sms_code_errmsg': '输入短信验证码有误'})

        # 保存注册数据
        try:
            user = User.objects.create_user(username=username, password=password, mobile=mobile)
        except DatabaseError as e:
            print(e)
            return render(request, 'register.html', {'register_errmsg': '注册失败'})

        # 实现状态保持
        login(request, user)

        response = redirect(reverse('contents:index'))
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        # 响应注册结果
        return response
