#!C:\Users\Wsmart\Envs\meiduo_mall\Scripts\python.exe
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "meiduo_mall.settings.dev")

# 对django进行初始化:
import django

django.setup()

from django.template import loader

from django.conf import settings
from goods.models import SKU
from goods.utils import get_breadcrumb, get_goods_and_spec, get_categories


def generate_detail_html_page(sku_id):
    '''
    生成详情页静态页面
    :return:
    '''
    categories = get_categories()

    # 获取商品所有规格选项:
    # 获取当前sku的信息
    sku = SKU.objects.get(id=sku_id)  # sku: iphonex 具体的商品
    sku.images = sku.skuimage_set.all()

    # 面包屑导航信息中的频道
    goods = sku.goods  # IPHONEX: 类别

    # 构建当前商品的规格键
    # sku_key = [规格1参数id， 规格2参数id， 规格3参数id, ...]
    sku_specs = sku.skuspecification_set.order_by('spec_id')  # 灰: 1 + 256: a
    sku_key = []  # 一个具体的商品对应的选项:[1, a]
    for spec in sku_specs:
        sku_key.append(spec.option.id)

    # 获取当前商品的所有SKU
    skus = goods.sku_set.all()

    # 构建不同规格参数（选项）的sku字典
    # spec_sku_map = {
    #     (规格1参数id, 规格2参数id, 规格3参数id, ...): sku_id,
    #     (规格1参数id, 规格2参数id, 规格3参数id, ...): sku_id,
    #     ...
    # }

    # 灰: 1   金色: 2
    # 256: a  64: b
    spec_sku_map = {}
    for s in skus:
        # 获取sku的规格参数
        s_specs = s.skuspecification_set.order_by('spec_id')
        # 用于形成规格参数-sku字典的键
        key = []  # 一个商品:[2, b]  另一个商品:[1, a]  [1, b] [2, a]
        for spec in s_specs:
            key.append(spec.option.id)
        # 向规格参数-sku字典添加记录
        spec_sku_map[tuple(key)] = s.id

        # {(商品选项1, 商品选项1): sku_id}
        # {(2,b):123, (1,a):124, (1,b):231, (2,a):234}

    goods_specs = goods.goodsspecification_set.order_by('id')  # [颜色, 内存]
    # goods_specs = goods.specs.order_by('id')
    # 若当前sku的规格信息不完整，则不再继续
    if len(sku_key) < len(goods_specs):
        return

    #  enumerate(goods_specs) ===> [0,颜色] [1, 内存]
    for index, spec in enumerate(goods_specs):
        # 复制当前sku的规格键
        # key = [规格1参数id， 规格2参数id， 规格3参数id, ...]
        key = sku_key[:]  # [1, a]
        # 该规格的选项
        spec_options = spec.specificationoption_set.all()  # 金色 灰色

        for option in spec_options:  # 金色# 2
            # 在规格参数sku字典中查找符合当前规格的sku
            key[index] = option.id  # key:[2, a]
            option.sku_id = spec_sku_map.get(tuple(key))

        spec.spec_options = spec_options

    data = {
        'goods': goods,
        'goods_specs': goods_specs,
        'sku': sku
    }

    breadcrumb = get_breadcrumb(data.get('goods').category3)

    # 拼接参数，生成静态 html 文件
    context = {
        'categories': categories,
        'goods': data.get('goods'),
        'specs': data.get('goods_specs'),
        'sku': data.get('sku'),
        'breadcrumb': breadcrumb
    }

    # return render(request, 'detail.html', context=context)

    template = loader.get_template('detail.html')
    html_text = template.render(context)
    file_path = os.path.join(settings.STATICFILES_DIRS[0], 'detail/' + str(sku_id) + '.html')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html_text)


if __name__ == '__main__':
    skus = SKU.objects.all()

    for sku in skus:
        print(sku.id)
        generate_detail_html_page(sku.id)
