from django.conf.urls import url
from . import views

urlpatterns = [
    # 购物车查询和新增和修改和删除
    url(r'^carts/$', views.CartsView.as_view(), name='info'),
    # 购物车全选
    url(r'^carts/selection/$', views.CartsSelectAllView.as_view()),
    # 提供商品页面右上角购物车数据
    url(r'^carts/simple/$', views.CartsSimpleView.as_view()),
]
