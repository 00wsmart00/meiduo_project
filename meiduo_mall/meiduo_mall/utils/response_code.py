# coding:utf-8

class RET:
    OK                  = "0"
    DBERR               = "4001"
    NODATA              = "4002"
    DATAEXIST           = "4003"
    DATAERR             = "4004"
    SESSIONERR          = "4101"
    LOGINERR            = "4102"
    PARAMERR            = "4103"
    USERERR             = "4104"
    ROLEERR             = "4105"
    PWDERR              = "4106"
    CPWDERR             = "4107"
    MOBILEERR           = "4108"
    REQERR              = "4201"
    IPERR               = "4202"
    THIRDERR            = "4301"
    IOERR               = "4302"
    SERVERERR           = "4500"
    UNKOWNERR           = "4501"
    NECESSARYPARAMERR   = "4502"
    SMSCODERR           = "4503"
    ALLOWERR            = "4504"


error_map = {
    RET.OK                    : u"成功",
    RET.DBERR                 : u"数据库查询错误",
    RET.NODATA                : u"无数据",
    RET.DATAEXIST             : u"数据已存在",
    RET.DATAERR               : u"数据错误",
    RET.SESSIONERR            : u"用户未登录",
    RET.LOGINERR              : u"用户登录失败",
    RET.PARAMERR              : u"参数错误",
    RET.USERERR               : u"用户不存在或未激活",
    RET.ROLEERR               : u"用户身份错误",
    RET.PWDERR                : u"密码错误",
    RET.CPWDERR               : u"密码不一致",
    RET.MOBILEERR             : u"手机号错误",
    RET.REQERR                : u"非法请求或请求次数受限",
    RET.IPERR                 : u"IP受限",
    RET.THIRDERR              : u"第三方系统错误",
    RET.IOERR                 : u"文件读写错误",
    RET.SERVERERR             : u"内部错误",
    RET.UNKOWNERR             : u"未知错误",
    RET.NECESSARYPARAMERR     : u"缺少必传参数",
    RET.SMSCODERR             : u"短信验证码有误",
    RET.ALLOWERR              : u"未勾选协议",
}



# coding:utf-8

class RETCODE:
    OK                  = "0"
    IMAGECODEERR        = "4001"
    THROTTLINGERR       = "4002"
    NECESSARYPARAMERR   = "4003"
    USERERR             = "4004"
    PWDERR              = "4005"
    CPWDERR             = "4006"
    MOBILEERR           = "4007"
    SMSCODERR           = "4008"
    ALLOWERR            = "4009"
    SESSIONERR          = "4101"
    DBERR               = "5000"
    EMAILERR            = "5001"
    TELERR              = "5002"
    NODATAERR           = "5003"
    NEWPWDERR           = "5004"
    OPENIDERR           = "5005"
    PARAMERR            = "5006"
    STOCKERR            = "5007"


err_msg = {
    RETCODE.OK                 : u"成功",
    RETCODE.IMAGECODEERR       : u"图形验证码错误",
    RETCODE.THROTTLINGERR      : u"访问过于频繁",
    RETCODE.NECESSARYPARAMERR  : u"缺少必传参数",
    RETCODE.USERERR            : u"用户名错误",
    RETCODE.PWDERR             : u"密码错误",
    RETCODE.CPWDERR            : u"密码不一致",
    RETCODE.MOBILEERR          : u"手机号错误",
    RETCODE.SMSCODERR          : u"短信验证码有误",
    RETCODE.ALLOWERR           : u"未勾选协议",
    RETCODE.SESSIONERR         : u"用户未登录",
    RETCODE.DBERR              : u"数据错误",
    RETCODE.EMAILERR           : u"邮箱错误",
    RETCODE.TELERR             : u"固定电话错误",
    RETCODE.NODATAERR          : u"无数据",
    RETCODE.NEWPWDERR          : u"新密码数据",
    RETCODE.OPENIDERR          : u"无效的openid",
    RETCODE.PARAMERR           : u"参数错误",
    RETCODE.STOCKERR           : u"库存不足",
}
