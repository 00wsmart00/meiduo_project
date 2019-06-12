var vm = new Vue({
    el: '#app',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host: host,
        old_pwd: '',
        new_pwd: '',
        new_cpwd: '',
        error_opwd: false,
        error_pwd: false,
        error_cpwd: false
    },
    methods: {
        // 检查旧密码
        check_opwd(){
        	var re = /^[0-9A-Za-z]{8,20}$/;
            if (re.test(this.old_pwd)) {
                this.error_opwd = false;
            } else {
                this.error_opwd = true;
            }
        },
        // 检查新密码
        check_pwd(){
        	var re = /^[0-9A-Za-z]{8,20}$/;
            if (re.test(this.new_pwd)) {
                this.error_pwd = false;
            } else {
                this.error_pwd = true;
            }
        },
        // 检查确认密码
        check_cpwd: function(){
            if (this.new_pwd != this.new_cpwd) {
                this.error_cpwd = true;
            } else {
                this.error_cpwd = false;
            }
        },
        // 提交修改密码
        on_submit: function(){
            this.check_opwd();
            this.check_pwd();
            this.check_cpwd();

            if (this.error_opwd==true || this.error_pwd==true || this.error_cpwd==true) {
                // 不满足修改密码条件：禁用表单
				window.event.returnValue = false
            }
        },
    }
});









// 提交修改密码
// on_submit: function(){
//             this.check_opwd();
//             this.check_pwd();
//             this.check_cpwd();
//
//             if (this.error_opwd==false && this.error_pwd==false && this.error_cpwd==false) {
//                 var url = this.host + '/password/';
//                 axios.put(url, {
//                             old_pwd: this.old_pwd,
//                             new_pwd: this.new_pwd,
//                             new_cpwd: this.new_cpwd
//                         }, {
//                             headers: {
//                                 'X-CSRFToken':getCookie('csrftoken')
//                             },
//                             responseType: 'json'
//                         }
//                     )
//                     .then(response => {
//                         if (response.data.code == '0') {
//                             location.href = '/login/';
//                         } else if (response.data.code == '4003') {
//                             alert(response.data.errmsg);
//                         } else if (response.data.code == '4005') {
//                             this.error_opwd = true;
//                         } else if (response.data.code == '5004') {
//                             this.error_npwd = true;
//                         } else if (response.data.code == '4006') {
//                             this.error_cpwd = true;
//                         } else { // 5000
//                             alert(response.code.errmsg);
//                         }
//                     })
//                     .catch(error => {
//                         console.log(error.response);
//                     })
//             }
//         },









// $(function () {
//     var error_old_pwd = false;
//     var error_new_pwd = false;
//     var error_new_cpwd = false;
//
//     $('.old_pwd').blur(function () {
//         check_old_pwd();
//     });
//
//     $('.new_pwd').blur(function () {
//         check_new_pwd();
//     });
//
//     $('.new_cpwd').blur(function () {
//         check_new_cpwd();
//     });
//
//     // 校验原始密码
// 	function check_old_pwd(){
// 		var len = $('.old_pwd').val().length;
// 		if(len<8||len>20) {
// 			$('.old_pwd_error').html('请输入8-12位的密码');
// 			error_old_pwd = true;
// 		} else {
// 			$('.old_pwd_error').empty();
// 			error_password = false;
// 		}
// 	}
//
// 	// 校验新密码
// 	function check_new_pwd(){
// 		var len = $('.new_pwd').val().length;
// 		if(len<8||len>20) {
// 			$('.new_pwd_error').html('请输入8-12位的密码');
// 			error_new_pwd = true;
// 		} else {
// 			$('.new_pwd_error').empty();
// 			error_new_pwd = false;
// 		}
// 	}
//
// 	// 校验确认密码c
// 	function check_new_cpwd(){
// 		var new_pwd = $('.new_pwd').val();
// 		var new_cpwd = $('.new_cpwd').val();
//
// 		if(new_pwd!=new_cpwd) {
// 			$('.new_cpwd_error').html('两次输入的密码不一致');
// 			error_new_cpwd = true;
// 		} else {
// 			$('.new_cpwd_error').empty();
// 			error_new_cpwd = false;
// 		}
// 	}
//
// 	// 点击修改密码确定标签
//     $('.change_pwd').submit(function() {
//
//         check_old_pwd();
// 		check_new_pwd();
// 		check_new_cpwd();
//
// 		if (error_old_pwd == false && error_new_pwd == false && error_new_cpwd == false) {
//             return true;
//         } else {
//             return false;
//         }
// 	});
// });