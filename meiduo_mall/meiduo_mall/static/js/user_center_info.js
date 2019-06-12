var vm = new Vue({
    el: '#app',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host: host,
        username: username,
        mobile: mobile,
        email: email,
        email_active: email_active,
        set_email: false,
        error_email: false,
        error_email_message: '',
        send_email_btn_disabled: false,
        send_email_tip: '重新发送验证邮件',
        histories: []
    },
    // ES6语法
    mounted() {
        // 额外处理用户数据
        this.email_active = (this.email_active=='True') ? true : false;
        this.set_email = (this.email=='') ? true : false;

        // 请求浏览历史记录
        this.browse_histories();
    },
    methods: {
        // 检查email格式
        check_email(){
            var re = /^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$/;
            if (re.test(this.email)) {
                this.error_email = false;
            } else {
                this.error_email_message = '邮箱格式错误';
                this.error_email = true;
                return;
            }
        },
        // 取消保存
        cancel_email(){
            this.email = '';
            this.error_email = false;
        },
        // 保存email
        save_email(){
            // 检查email格式
            this.check_email();

            if (this.error_email == false) {
                var url = this.host + '/emails/';
                axios.put(url, {
                        email: this.email
                    }, {
                        headers: {
                            'X-CSRFToken':getCookie('csrftoken')
                        },
                        responseType: 'json'
                    })
                    .then(response => {
                        if (response.data.code == '0') {
                            this.set_email = false;
                            this.send_email_btn_disabled = true;
                            this.send_email_tip = '已发送验证邮件';
                        } else if (response.data.code == '4101') {
                            location.href = '/login/?next=/info/';
                        } else { // 5000 5001
                            this.error_email_message = response.data.errmsg;
                            this.error_email = true;
                        }
                    })
                    .catch(error => {
                        console.log(error.response);
                    });
            }
        },
        // 请求浏览历史记录
        browse_histories(){
            var url = this.host + '/browse_histories/';
            axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    this.histories = response.data.skus;
                    for(var i=0; i<this.histories.length; i++){
                        this.histories[i].url = '/goods/' + this.histories[i].id + '.html';
                    }
                })
                .catch(error => {
                    console.log(error.response);
                })
        }
    }
});












// var email_error = false;
//
// $(function () {
//
// });
//
// function save_email() {
//     // 前端校验邮箱地址格式
//     check_email();
//     if (email_error) {
//         alert('请输入正确格式的邮箱');
//         return;
//     }
//
//     var params = {
//         'email':$('.email').val()
//     };
//
//     $.ajax({
//         url: '/emails/',
//         type: 'post',
//         data: JSON.stringify(params),
//         contentType: 'application/json',
//         headers: {'X-CSRFToken':getCookie('csrftoken')},
//         success:function (response) {
//             if (response.code == "0") {
//                 $('.email').attr("disabled","disabled");
//                 $('.save_email').hide();
//                 $('.reset_email').hide();
//                 $('.resend_email').show();
//             } else if (response.code == "4101") {
//                 // 用户未登录
//                 location.href = '/login/?next=/info/';
//             } else {
//                 console.log(response);
//                 alert(response.errmsg);
//             }
//         }
//     });
// }
//
// function reset_email() {
//     $('.email').val("");
// }
//
// // 校验邮箱
// function check_email() {
//     var email = $('.email').val();
//     var re = /^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$/;
//
//     if(!re.test(email)) {
//         email_error = true;
//     } else {
//         email_error = false;
//     }
// }


