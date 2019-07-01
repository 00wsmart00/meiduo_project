from collections import OrderedDict

from django.shortcuts import render

from goods.models import GoodsChannel, SKU


def get_goods_and_spec(sku_id, request):
    # 获取当前sku的信息
    try:
        sku = SKU.objects.get(id=sku_id) # iphone sku
        sku.images = sku.skuimage_set.all()
    except SKU.DoesNotExist:
        return render(request, '404.html')

    # 面包屑导航信息中的频道
    goods = sku.goods # IPHONE spu
    goods.channel = goods.category1.goodschannel_set.all()[0]
    # 构建当前商品的规格键
    # sku_key = [规格1参数id， 规格2参数id， 规格3参数id, ...]
    sku_specs = sku.skuspecification_set.order_by('spec_id')  # 金 64
    sku_key = []
    for spec in sku_specs:
        # spec : 金 1    64  a

        sku_key.append(spec.option.id)  # [1,a]

    # 获取当前商品的所有SKU
    skus = goods.sku_set.all()

    spec_sku_map = {}   # {(1,a):sku_id1,(1,b):sku_id2......}
    for s in skus:       # s:4种机型
        # 获取sku的规格参数
        s_specs = s.skuspecification_set.order_by('spec_id')
        # 用于形成规格参数-sku字典的键
        key = []
        for spec in s_specs:
            key.append(spec.option.id)
        # 向规格参数-sku字典添加记录
        spec_sku_map[tuple(key)] = s.id
    # 颜色 内存
    goods_specs = goods.goodsspecification_set.order_by('id')
    # 若当前sku的规格信息不完整，则不再继续
    if len(sku_key) < len(goods_specs):
        return
    for index, spec in enumerate(goods_specs):  # [0,颜色] [1,内存]
        # 复制当前sku的规格键
        key = sku_key[:]   # [1,a]
        # 该规格的选项
        # 颜色 金  灰  内存 64 256
        spec_options = spec.specificationoption_set.all()
        # spec_options = spec.options.all()
        for option in spec_options:
            # 在规格参数sku字典中查找符合当前规格的sku
            key[index] = option.id  # key=[2,a]   key=[1,a] [1,b]
            option.sku_id = spec_sku_map.get(tuple(key))
            print(key)

        # spec.options = spec_options
        spec.spec_options = spec_options

    data = {
        'goods': goods,
        'goods_specs': goods_specs,
        'sku': sku
    }

    return data


def get_categories():
    """获取商品的分类菜单"""
    # 第一部分: 从数据库中取数据:
    # 定义一个有序字典对象
    categories = OrderedDict()
    # 对 GoodsChannel 进行 group_id 和 sequence 排序, 获取排序后的结果:
    channels = GoodsChannel.objects.order_by('group_id', 'sequence')
    # 遍历排序后的结果: 得到所有的一级菜单( 即,频道 )
    for channel in channels:
        # 从频道中得到当前的 组id
        group_id = channel.group_id

        # 判断: 如果当前 组id 不在我们的有序字典中:
        if group_id not in categories:
            # 我们就把 组id 添加到 有序字典中
            # 并且作为 key值, value值 是 {'channels': [], 'sub_cats': []}
            categories[group_id] = {'channels': [], 'sub_cats': []}

        # 获取当前频道的分类名称
        cat1 = channel.category

        # 给刚刚创建的字典中, 追加具体信息:
        # 即, 给'channels' 后面的 [] 里面添加如下的信息:
        categories[group_id]['channels'].append({
            'id': cat1.id,
            'name': cat1.name,
            'url': channel.url
        })

        # 根据 cat1 的外键反向, 获取下一级(二级菜单)的所有分类数据, 并遍历:
        for cat2 in cat1.goodscategory_set.all():
            # 创建一个新的列表:
            cat2.sub_cats = []
            # 根据 cat2 的外键反向, 获取下一级(三级菜单)的所有分类数据, 并遍历:
            for cat3 in cat2.goodscategory_set.all():
                # 拼接新的列表: key: 二级菜单名称, value: 三级菜单组成的列表
                cat2.sub_cats.append(cat3)
            # 所有内容在增加到 一级菜单生成的 有序字典中去:
            categories[group_id]['sub_cats'].append(cat2)

    return categories


def get_breadcrumb(category):
    """
    获取面包屑导航
    :param category: 商品类别
    :return:面包屑导航字典
    """
    # 1.定义一个字典
    breadcrumb = dict(
        cat1='',
        cat2='',
        cat3=''
    )
    # 2.判断category是哪一个级别的,category是GoodsCategory的对象
    if category.parent is None:
        # 当前类别是第一级别的
        breadcrumb['cat1'] = category
    # 自关联表的对象还是自己
    elif category.goodscategory_set.count() == 0:
        # 当前类别是三级
        breadcrumb['cat3'] = category
        cat2 = category.parent
        breadcrumb['cat2'] = cat2
        breadcrumb['cat1'] = cat2.parent
    else:
        # 当前类别是二级
        breadcrumb['cat2'] = category
        breadcrumb['cat1'] = category.parent
    # 3.返回
    return breadcrumb
