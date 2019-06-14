from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer, BadData


def generate_access_token(openid):
    """
    生成access_token
    :param openid: 用户的id
    :return: access_token
    """
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY, 600)

    data = {'openid': openid}

    token = serializer.dumps(data)
    return token.decode()

def check_access_token(access_token):
    """
    检验检验用户传入的 token
    :param access_token:token
    :return:
    """
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                 expires_in=600)

    try:
        # 尝试使用对象的 loads 函数
        # 对 access_token 进行反序列化( 类似于解密 )
        # 查看是否能够获取到数据:
        data = serializer.loads(access_token)

    except BadData:
        # 如果出错, 则说明 access_token 里面不是我们认可的.
        # 返回 None
        return None
    else:
        # 如果能够从中获取 data, 则把 data 中的 openid 返回
        return data.get('openid')

