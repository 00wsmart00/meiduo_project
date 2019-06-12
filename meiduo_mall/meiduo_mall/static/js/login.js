var vm = new Vue({
    el: '#app',
	// 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host,
        error_username: false,
		error_pwd_message: '',
        error_pwd: false,
        username: '',
        password: '',
        remembered: false
    },
    methods: {
        // 检查账号
        check_username: function(){
        	var re = /^[a-zA-Z0-9_-]{5,20}$/;
			if (re.test(this.username)) {
                this.error_username = false;
            } else {
                this.error_username = true;
            }
        },
		// 检查密码
        check_pwd: function(){
        	var re = /^[0-9A-Za-z]{8,20}$/;
			if (re.test(this.password)) {
                this.error_pwd = false;
            } else {
                this.error_pwd = true;
            }
        },
        // 表单提交
        on_submit: function(){
            this.check_username();
            this.check_pwd();

            if (this.error_username == true || this.error_pwd == true) {
                // 不满足登录条件：禁用表单
				window.event.returnValue = false
            }
        },
        // qq登录
        qq_login: function(){
            var next = get_query_string('next') || '/';
            var url = this.host + '/qq/authorization/?next=' + next;
            axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    location.href = response.data.login_url;
                })
                .catch(error => {
                    console.log(error.response);
                })
        }
    }
});








// // 表单提交
//         on_submit: function(){
//             this.check_username();
//             this.check_pwd();
//
//             if (this.error_username == false && this.error_pwd == false) {
//                 var url = this.host + '/login/';
//             	axios.post(url, {
//                         username: this.username,
//                         password: this.password,
//                         remembered: this.remembered.toString()
//                     }, {
//             	        headers: {
// 							'X-CSRFToken':getCookie('csrftoken')
// 						},
//                         responseType: 'json',
//                         withCredentials: true // 携带cookie
//                     })
//                     .then(response => {
//                         if (response.data.code == '0') {
//                             // 登录成功，跳转页面
//                             var return_url = get_query_string('next');
//                             if (!return_url) {
//                                 return_url = '/';
//                             }
//                             location.href = return_url;
//                         } else {
//                             if (response.data.code == '4003') {
//                                 alert(response.data.errmsg);
//                             } else if (response.data.code == '4004') {
//                                 this.error_username = true;
//                             } else { // 4005
//                                 this.error_pwd_message = response.data.errmsg;
//                                 this.error_pwd = true;
//                             }
//                         }
//                     })
//                     .catch(error => {
//                         console.log(error.response);
//                     })
//             }
//         },









// var error_name = true;
// var error_password = true;
//
// $(function () {
//     $('.name_input').blur(function () {
//         check_user_name();
//     });
//
//     $('.pass_input').blur(function () {
//         check_pwd();
//     });
//
//     // 校验用户名
// 	function check_user_name(){
// 		var re = /^[a-zA-Z0-9_-]{5,20}$/;
// 		var username = $('.name_input').val();
//
// 		if(re.test(username)) {
// 			$('.user_error').empty();
// 			error_name = false;
// 		} else {
// 			$('.user_error').html('请输入5-20个字符的用户名');
// 			error_name = true;
// 		}
// 	}
//
// 	// 校验密码
// 	function check_pwd(){
// 		var re = /^[0-9A-Za-z]{8,20}$/;
// 		var pwd = $('.pass_input').val();
// 		if(re.test(pwd)) {
// 			$('.pwd_error').empty();
// 			error_password = false;
// 		} else {
// 			$('.pwd_error').html('请输入8-20位的密码');
// 			error_password = true;
// 		}
// 	}
//
// 	// 点击登录标签
//     $('.login').submit(function() {
//
//         // check_user_name();
// 		// check_pwd();
//
// 		if(error_name == false && error_password == false) {
// 		    return true
// 		} else {
// 			alert('请输入完整登录信息');
// 			return false;
// 		}
// 	});
// });
//
//
// // QQ登录
// function qq_login() {
// 	// 获取next参数
// 	var next = this.get_query_string('next') || '/';
//
// 	// QQ登录扫码页面
// 	var url = '/qq/authorization/?next=' + next;
// 	$.get(url, function (resposne) {
// 		if (resposne.code == '0') {
// 			location.href = resposne.login_url;
// 		} else {
// 			alert(resposne.errmsg);
// 			console.log(response);
// 		}
// 	});
// }

