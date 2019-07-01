import datetime

from django import http
from django.core.paginator import Paginator, EmptyPage

from django.shortcuts import render

# Create your views here.
from django.utils import timezone
from django.views import View

from goods.models import GoodsCategory, SKU, GoodsVisitCount
from goods.utils import get_categories, get_breadcrumb, get_goods_and_spec
from meiduo_mall.utils.response_code import RETCODE
import logging

from orders.models import OrderGoods

logger = logging.getLogger()


class GoodsCommentView(View):
    """订单商品评价信息"""

    def get(self, request, sku_id):
        # 获取被评价的订单商品信息
        order_goods_list = OrderGoods.objects.filter(sku_id=sku_id)
        # 序列化
        comment_list = []
        for order_goods in order_goods_list:
            username = order_goods.order.user.username
            comment_list.append({
                'username': username[0] + '***' + username[-1] if order_goods.is_anonymous else username,
                'comment': order_goods.comment,
                'score': order_goods.score,
            })
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'goods_comment_list': comment_list})


class DetailVisitView(View):
    """详情页分类商品访问量"""

    def post(self, request, category_id):
        """记录分类商品访问量"""
        # 根据传入的category_id值，获取对应类别的商品
        try:
            category = GoodsCategory.objects.get(id=category_id)
        except GoodsCategory.DoesNotExist:
            return http.HttpResponseForbidden('缺少必传参数')

        # 获取今天的日期:
        # 先获取时间对象
        t = timezone.localtime()
        # 根据时间对象拼接日期的字符串形式:
        today_str = '%d-%02d-%02d' % (t.year, t.month, t.day)
        # 将字符串转换成日期格式:
        today_date = datetime.datetime.strptime(today_str, '%Y-%m-%d')
        try:
            # 将今天的日期传入进去,获得该商品今天的访问量
            # 查询今天该类别的商品的访问量
            counts_data = category.goodsvisitcount_set.get(date=today_date)
        except GoodsVisitCount.DoesNotExist:
            # 如果该商品在今天没有访问记录,就新建一个目录
            counts_data = GoodsVisitCount()

        try:
            # 更新模型类里面的属性:category和count
            counts_data.category = category
            counts_data.count += 1
            counts_data.save()
        except Exception as e:
            logger.error(e)
            return http.HttpResponseServerError('服务器异常')

        # 返回:
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok'

        })


class DetailView(View):
    """商品详情页"""

    def get(self, request, sku_id):
        """提供商品详情页"""
        # 商品分类菜单
        categories = get_categories()
        try:
            sku = SKU.objects.get(id=sku_id)
            sku.images = sku.skuimage_set.all()
        except SKU.DoesNotExist:
            return render(request, '404.html')

        # 面包屑导航
        category = sku.category
        breadcrumb = get_breadcrumb(category)
        # 调用封装的函数, 根据 sku_id 获取对应的
        # 1. 类别( sku )
        # 2. 商品( goods )
        # 3. 商品规格( spec )
        data = get_goods_and_spec(sku_id, request)

        # 拼接参数，生成静态 html 文件
        context = {
            'categories': categories,
            'goods': data.get('goods'),
            'specs': data.get('goods_specs'),
            'sku': data.get('sku'),
            'breadcrumb':breadcrumb,
        }

        return render(request, 'detail.html', context)


class HotGoodsView(View):
    """商品热销排行"""

    def get(self, request, category_id):
        """提供商品热销排行 Json数据"""
        # 根据销量倒序
        skus = SKU.objects.filter(category_id=category_id,
                                  is_launched=True).order_by('-sales')[:2]

        # 序列化
        hot_skus = []
        for sku in skus:
            hot_skus.append({
                'id': sku.id,
                'default_image_url': sku.default_image_url,
                'name': sku.name,
                'price': sku.price
            })

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'hot_skus': hot_skus})


class ListView(View):
    """商品列表页"""

    def get(self, request, category_id, page_num):
        """提供商品列表页"""
        try:
            # 获取三级菜单分类信息:
            category = GoodsCategory.objects.get(id=category_id)
        except GoodsCategory.DoesNotExist:
            return http.HttpResponseNotFound('GoodsCategory 不存在')
        # 查询商品频道分类
        categories = get_categories()

        # 查询面包屑导航
        breadcrumb = get_breadcrumb(category)
        sort = request.GET.get('sort', 'default')
        # 按照排序规则查询该分类商品的sku信息
        if sort == 'price':
            # 按照价格由低到高
            sortkind = 'price'
        elif sort == 'hot':
            # 按照销量由高到低
            sortkind = '-sales'
        else:
            sort = 'default'
            sortkind = 'create_time'

        skus = SKU.objects.filter(category=category, is_launched=True).order_by(sortkind)

        # 创建分页器:每页N条记录
        # # 列表页每页商品数据量
        # GOODS_LIST_LIMIT = 5
        paginator = Paginator(skus, 5)
        # 获取每页商品的数据
        try:
            page_skus = paginator.page(page_num)

        except EmptyPage:
            # 如果page_num 不正确,默认给用户404
            return http.HttpResponseNotFound('empty page')

        # 获取列表的总页数
        total_page = paginator.num_pages

        # 渲染页面
        context = {
            'categories': categories,
            'breadcrumb': breadcrumb,
            'sort': sort,  # 排序字段
            'category': category,  # 第三级分类
            'page_skus': page_skus,  # 分页后数据
            'total_page': total_page,  # 总页数
            'page_num': page_num,  # 当前页码
        }
        return render(request, 'list.html', context)
