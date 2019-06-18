from django.conf.urls import url
from . import views
urlpatterns = [
    # 获取省份信息:
    url(r'^areas/$', views.ProvinceAreasView.as_view()),
    # 子级地区
    url(r'^areas/(?P<pk>[1-9]\d+)/$', views.SubAreasView.as_view()),
]
