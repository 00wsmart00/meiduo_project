from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import render

# Create your views here.
from django.views import View

from areas.models import Area
from meiduo_mall.utils.response_code import RETCODE


class ProvinceAreasView(View):
    """省级地区"""

    def get(self, request):
        """
        提供省级地区的数据
        1.查询省级数据
        2.序列化省级数据
        3.响应省级数据
        4.补充缓存逻辑
        """
        # 增加: 判断是否有缓存
        province_list = cache.get('province_list')
        if not province_list:
            # 1.查询省级数据
            try:
                province_model_list = Area.objects.filter(parent__isnull=True)

                # 2.整理省级数据
                province_list = []
                for province_model in province_model_list:
                    province_list.append({'id': province_model.id,
                                          'name': province_model.name})
                # 增加: 缓存省级数据
                cache.set('province_list', province_list, 3600)
            except Exception as e:
                # 报错,则返回错误原因
                # DBERR:5000
                return JsonResponse({
                    'code': RETCODE.DBERR,
                    'errmsg': '省份数据错误'
                })

        # 3.响应省级数据
        return JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'OK',
            'province_list': province_list
        })


class SubAreasView(View):
    """子级地区,市和县"""

    def get(self, request, pk):
        """
        提供市或区地区数据
        1.查询市或区数据
        2.序列化市或区数据
        3.响应市或区数据
        4.补充缓存数据
        """
        # 判断是否有缓存
        sub_data = cache.get('sub_area_' + pk)
        if not sub_data:
            # 1.查询市或区的数据
            try:
                sub_model_list = Area.objects.filter(parent=pk)
                parent_model = Area.objects.get(id=pk)

                # 2.整理市或区的数据
                sub_list = []
                for sub_model in sub_model_list:
                    sub_list.append({
                        'id': sub_model.id,
                        'name': sub_model.name
                    })
                sub_data = {
                    'id': parent_model.id,
                    'name': parent_model.name,
                    'subs': sub_list
                }
                # 缓存市或区数据
                cache.set('sub_area_' + pk, sub_data, 3600)
            except Exception as e:
                # DBERR: 5000
                return JsonResponse({'code': RETCODE.DBERR,
                                     'errmsg': '城市或区县数据错误'})
        # 3.响应市或区的数据
        return JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'OK',
            'sub_data': sub_data
        })
