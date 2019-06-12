var vm = new Vue({
	el: '.register_con',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
	data: {
		host: host,
		error_phone: false,
		error_password: false,
		error_image_code: false,
		error_sms_code: false,
		error_phone_message: '',
		error_image_code_message: '',
		error_sms_code_message: '',

		image_code_id: '', // 图片验证码id
		image_code_url: '',

		sms_code_tip: '获取短信验证码',
		sending_flag: false, // 正在发送短信标志

		password: '',
		mobile: '',
		image_code: '',
		sms_code: '',
		access_token: ''
	},
	mounted(){
		// 生成图形验证码
		this.generate_image_code();
		// 初始化access_token
		this.access_token = access_token;
	},
	methods: {
		// 生成一个图片验证码的编号，并设置页面中图片验证码img标签的src属性
		generate_image_code(){
			// 生成一个编号 : 严格一点的使用uuid保证编号唯一， 不是很严谨的情况下，也可以使用时间戳
			this.image_code_id = generateUUID();
			// 设置页面中图片验证码img标签的src属性
			this.image_code_url = this.host + "/image_codes/" + this.image_code_id + "/";
		},
		// 检查手机号
		check_phone(){
			var re = /^1[345789]\d{9}$/;
			if(re.test(this.mobile)) {
				this.error_phone = false;
			} else {
				this.error_phone_message = '您输入的手机号格式不正确';
				this.error_phone = true;
			}
		},
		// 检查密码
		check_pwd(){
			var re = /^[0-9A-Za-z]{8,20}$/;
			if (re.test(this.password)) {
				this.error_password = false;
			} else {
				this.error_password = true;
			}
		},
		// 检查图片验证码
		check_image_code(){
			if(!this.image_code) {
				this.error_image_code_message = '请填写图片验证码';
				this.error_image_code = true;
			} else {
				this.error_image_code = false;
			}
		},
		// 检查短信验证码
		check_sms_code(){
			if(!this.sms_code){
				this.error_sms_code_message = '请填写短信验证码';
				this.error_sms_code = true;
			} else {
				this.error_sms_code = false;
			}
		},
		// 发送手机短信验证码
		send_sms_code(){
			if (this.sending_flag == true) {
				return;
			}
			this.sending_flag = true;

			// 校验参数，保证输入框有数据填写
			this.check_phone();
			this.check_image_code();

			if (this.error_phone == true || this.error_image_code == true) {
				this.sending_flag = false;
				return;
			}

			// 向后端接口发送请求，让后端发送短信验证码
			var url = this.host + '/sms_codes/' + this.mobile + '/?image_code=' + this.image_code+'&image_code_id='+ this.image_code_id;
			axios.get(url, {
					responseType: 'json'
				})
				.then(response => {
					// 表示后端发送短信成功
					if (response.data.code == '0') {
						// 倒计时60秒，60秒后允许用户再次点击发送短信验证码的按钮
						var num = 60;
						// 设置一个计时器
						var t = setInterval(() => {
							if (num == 1) {
								// 如果计时器到最后, 清除计时器对象
								clearInterval(t);
								// 将点击获取验证码的按钮展示的文本回复成原始文本
								this.sms_code_tip = '获取短信验证码';
								// 将点击按钮的onclick事件函数恢复回去
								this.sending_flag = false;
							} else {
								num -= 1;
								// 展示倒计时信息
								this.sms_code_tip = num + '秒';
							}
						}, 1000, 60)
					} else {
						if (response.data.code == '4001') {
							this.error_image_code_message = response.data.errmsg;
							this.error_image_code = true;
                        } else { // 4002
							this.error_sms_code_message = response.data.errmsg;
							this.error_sms_code = true;
						}
						this.generate_image_code();
						this.sending_flag = false;
					}
				})
				.catch(error => {
					console.log(error.response);
					this.sending_flag = false;
				})
		},
		// 绑定openid
		on_submit(){
			this.check_pwd();
			this.check_phone();
			this.check_sms_code();

			if(this.error_password == true || this.error_phone == true || this.error_sms_code == true) {
				// 不满足条件：禁用表单
				window.event.returnValue = false
			}
		}
	}
});








// 绑定openid
// on_submit(){
// 			this.check_pwd();
// 			this.check_phone();
// 			this.check_sms_code();
//
// 			console.log(getCookie('csrftoken'));
//
// 			if(this.error_password == false && this.error_phone == false && this.error_sms_code == false) {
// 				axios.post(this.host + '/oauth_callback/', {
// 						mobile: this.mobile,
// 						password: this.password,
// 						sms_code: this.sms_code,
// 						access_token: this.access_token
// 					}, {
// 						headers: {
// 							'X-CSRFToken':getCookie('csrftoken')
// 						},
// 						responseType: 'json',
// 						withCredentials: true
// 					})
// 					.then(response => {
// 						if (response.data.code == '0') {
// 							// location.href = get_query_string('state');
// 							location.href = '/';
// 						} else {
// 							if (response.data.code == '4003') {
// 								alert(response.data.errmsg);
// 							} else if (response.data.code == '4007') {
// 								this.error_phone_message = response.data.errmsg;
// 								this.error_phone = true;
// 							} else if (response.data.code == '4005') {
// 								this.error_password = true;
// 							} else if (response.data.code == '4008') {
// 								this.error_sms_code_message = response.data.errmsg;
// 								this.error_sms_code = true;
// 							} else if (response.data.code == '4009') {
// 								this.error_allow = true;
// 							} else { // 5005
// 								alert(response.data.errmsg);
// 							}
// 						}
// 					})
// 					.catch(error => {
// 						console.log(error.response);
// 					})
// 			}
// 		}











// var error_phone = true;
// var error_password = true;
// var error_pic_code = true;
// var error_msg_code = true;
//
// $(function(){
// 	$('#phone').blur(function() {
// 		check_phone();
// 	});
//
// 	$('#pwd').blur(function() {
// 		check_pwd();
// 	});
//
// 	$('#pic_code').blur(function() {
// 		check_pic_code();
//     });
//
// 	$('#msg_code').blur(function() {
// 		check_msg_code();
// 	});
//
// 	// 校验手机号
// 	function check_phone(){
// 		var re = /^1[3-9]\d{9}$/;
// 		var mobile = $('#phone').val();
//
// 		if(re.test(mobile)) {
// 			$('#phone').next().empty();
// 			error_phone = false;
// 		} else {
// 			$('#phone').next().html('请输入正确的手机号码');
// 			error_phone = true;
// 		}
// 	}
//
// 	// 校验密码
// 	function check_pwd(){
// 		var len = $('#pwd').val().length;
// 		if(len<8||len>20) {
// 			$('#pwd').next().html('请输入8-20位密码');
// 			error_password = true;
// 		} else {
// 			$('#pwd').next().empty();
// 			error_password = false;
// 		}
// 	}
//
// 	// 校验图形验证码
// 	function check_pic_code(){
// 		var len = $('#pic_code').val().length;
// 		if(len!=4) {
// 			$('#pic_code').next().next().html('请填写图形验证码');
// 			error_pic_code = true;
// 		} else {
// 			$('#pic_code').next().next().empty();
// 			error_pic_code = false;
// 		}
// 	}
//
//     // 校验短信验证码
// 	function check_msg_code(){
// 		// var msg_code = $('#msg_code').val();
// 		var len = $('#msg_code').val().length;
// 		if(len!=6) {
// 			$('#msg_code').next().next().html('请填写短信验证码');
// 			error_msg_code = true;
// 		} else {
// 			$('#msg_code').next().next().empty();
// 			error_msg_code = false;
// 		}
// 	}
//
//     // 点击保存标签
//     $('#reg_form').submit(function() {
//
// 		// check_pwd();
// 		// check_phone();
// 		// check_msg_code();
//
// 		if(error_phone == false && error_password == false && error_msg_code == false)
// 		{
// 		    return true
// 		} else {
// 			alert('请输入完整绑定信息');
// 			return false;
// 		}
// 	});
//
// 	// 生成图片验证码
// 	generateImageCode();
// });
//
// var imageCodeId = "";
//
// // 生成一个图片验证码的编号，并设置页面中图片验证码img标签的src属性
// function generateImageCode() {
//     // 获取uuid
//     imageCodeId = generateUUID();
//     // 生成获取图片验证码的url
//     var url = '/image_codes/' + imageCodeId + '/';
//     // 将url设置到img标签的src数据
//     $('.pic_code').attr('src', url);
// }
//
// // 点击发送短信验证码
// function sendSMSCode() {
//     // 移除点击事件，避免重复点击
//     $(".get_msg_code").removeAttr("onclick");
//
//     // 校验参数，保证输入框有数据填写
//     var mobile = $("#phone").val();
//     var image_code = $('#pic_code').val();
//
//     if (error_phone==true || error_pic_code==true) {
//     	$(".get_msg_code").attr("onclick", "sendSMSCode();");
//     	return;
// 	}
//
//     // TODO 发送短信验证码
//     var url = '/sms_codes/' + mobile + '/?image_code=' + image_code + '&image_code_id=' + imageCodeId;
//     $.get(url, function (response) {
//         if (response.code == "0") {
//             // 发送成功后，进行倒计时
//             var num = 60;
//             var t = setInterval(function () {
//                 if (num == 0) {
//                     // 倒计时结束,清除定时器
//                     clearInterval(t); 
//                     // 倒计时结束,重置内容
//                     $(".get_msg_code").html('获取短信验证码');
//                     // 倒计时结束，重新添加点击事件
//                     $(".get_msg_code").attr("onclick", "sendSMSCode();");
//                     generateImageCode();
//                 } else {
//                     // 正在倒计时，显示秒数
//                     $(".get_msg_code").html(num + '秒');
//                 }
//                 // 每一秒减一
//                 num -= 1;
//             }, 1000);
//         } else if (response.code == '4201') {
//         	// 展示频繁发送短信的错误提示信息
//         	$('#msg_code').next().next().html("发送短信过于频繁");
// 			$('#msg_code').next().next().show();
// 			// 重新添加点击事件
//             $(".get_msg_code").attr("onclick", "sendSMSCode();");
// 		} else {
//             alert(response.errmsg);
//             // 重新添加点击事件
//             $(".get_msg_code").attr("onclick", "sendSMSCode();");
//             generateImageCode();
//         }
//     });
// }
//
// function generateUUID() {
//     var d = new Date().getTime();
//     if(window.performance && typeof window.performance.now === "function"){
//         d += performance.now(); //use high-precision timer if available
//     }
//     var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
//         var r = (d + Math.random()*16)%16 | 0;
//         d = Math.floor(d/16);
//         return (c=='x' ? r : (r&0x3|0x8)).toString(16);
//     });
//     return uuid;
// }
//
