var vm = new Vue({
    el: '#app',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host,
        is_show_edit: false,
        provinces: [],
        cities: [],
        districts: [],
        form_address: {
            title: '',
            receiver: '',
            province_id: '',
            city_id: '',
            district_id: '',
            place: '',
            mobile: '',
            tel: '',
            email: '',
        },
        error_receiver: false,
        error_place: false,
        error_mobile: false,
        error_tel: false,
        error_email: false,
        addresses: [],
        editing_address_index: '',
        default_address_id: '',
        edit_title_index: '',
        input_title: '',

    },
    mounted(){
        // 获取省份数据
        this.get_provinces();
        // 将用户地址列表绑定到变量, addresses 是django模板传给vue的json字符串
        this.addresses = JSON.parse(JSON.stringify(addresses));
        // 默认地址id
        this.default_address_id = default_address_id;
    },
    watch: {
        // 监听到省份id变化
        'form_address.province_id': function(){
            if (this.form_address.province_id) {
                var url = this.host + '/areas/' + this.form_address.province_id + '/';
                axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    if (response.data.code == '0') {
                        this.cities = response.data.sub_data.subs;
                    } else {
                        console.log(response.data);
                        this.cities = [];
                    }
                })
                .catch(error => {
                    console.log(error.response);
                    this.cities = [];
                });
            }
        },
        // 监听到城市id变化
        'form_address.city_id': function(){
            if (this.form_address.city_id){
                var url = this.host + '/areas/'+ this.form_address.city_id + '/';
                axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    if (response.data.code == '0') {
                        this.districts = response.data.sub_data.subs;
                    } else {
                        console.log(response.data);
                        this.districts = [];
                    }
                })
                .catch(error => {
                    console.log(error.response);
                    this.districts = [];
                });
            }
        }
    },
    methods: {
        // 获取省份数据
        get_provinces(){
            var url = this.host + '/areas/';
            axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    if (response.data.code == '0') {
                        this.provinces = response.data.province_list;
                    } else {
                        console.log(response.data);
                        this.provinces = [];
                    }
                })
                .catch(error => {
                    console.log(error.response);
                    this.provinces = [];
                });
        },
        check_receiver(){
            if (!this.form_address.receiver) {
                this.error_receiver = true;
            } else {
                this.error_receiver = false;
            }
        },
        check_place(){
            if (!this.form_address.place) {
                this.error_place = true;
            } else {
                this.error_place = false;
            }
        },
        check_mobile(){
            var re = /^1[345789]\d{9}$/;
            if(re.test(this.form_address.mobile)) {
                this.error_mobile = false;
            } else {
                this.error_mobile = true;
            }
        },
        check_tel(){
            if (this.form_address.tel) {
                var re = /^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$/;
                if (re.test(this.form_address.tel)) {
                    this.error_tel = false;
                } else {
                    this.error_tel = true;
                }
            } else {
                this.error_tel = false;
            }
        },
        check_email(){
            if (this.form_address.email) {
                var re = /^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$/;
                if(re.test(this.form_address.email)) {
                    this.error_email = false;
                } else {
                    this.error_email = true;
                }
            } else {
                this.error_email = false;
            }
        },
        // 清空错误提示信息
        clear_all_errors(){
            this.error_receiver = false;
            this.error_mobile = false;
            this.error_place = false;
            this.error_tel = false;
            this.error_email = false;
        },
        // 展示新增地址弹框时
        show_add_site(){
            this.is_show_edit = true;
            this.clear_all_errors();
            this.editing_address_index = '';
            this.form_address.title = '';
            this.form_address.receiver = '';
            this.form_address.province_id = '';
            this.form_address.city_id = '';
            this.form_address.district_id = '';
            this.form_address.place = '';
            this.form_address.mobile = '';
            this.form_address.tel = '';
            this.form_address.email = '';
        },
        // 展示编辑地址弹框时
        show_edit_site(index){
            this.is_show_edit = true;
            this.clear_all_errors();
            this.editing_address_index = index.toString();
            // 只获取要编辑的数据，防止修改form_address影响到addresses数据
            this.form_address = JSON.parse(JSON.stringify(this.addresses[index]));
        },
        // 新增地址
        save_address(){
            if (this.error_receiver || this.error_place || this.error_mobile || this.error_email || !this.form_address.province_id || !this.form_address.city_id || !this.form_address.district_id ) {
                alert('信息填写有误！');
            } else {
                // 收货人默认就是收货地址标题
                this.form_address.title = this.form_address.receiver;
                // 注意：0 == '';返回true; 0 === '';返回false;
                if (this.editing_address_index === '') {
                    // 新增地址
                    var url = this.host + '/addresses/create/';
                    axios.post(url, this.form_address, {
                        headers: {
                            'X-CSRFToken':getCookie('csrftoken')
                        },
                        responseType: 'json'
                    })
                    .then(response => {
                        if (response.data.code == '0') {
                            location.reload();
                        } else if (response.data.code == '4101') {
                            location.href = '/login/?next=/addresses/';
                        }else if (response.data.code == '4007') {
                            this.error_mobile = true;
                        } else if (response.data.code == '5002') {
                            this.error_tel = true;
                        } else if (response.data.code == '5001') {
                            this.error_email = true;
                        } else { // 4002 4003 5000 (以提示框的形式出现)
                            alert(response.data.errmsg);
                        }
                    })
                    .catch(error => {
                        console.log(error.response);
                    });
                } else {
                    // 修改地址
                    var url = this.host + '/addresses/' + this.addresses[this.editing_address_index].id + '/';
                    axios.put(url, this.form_address, {
                        headers: {
                            'X-CSRFToken':getCookie('csrftoken')
                        },
                        responseType: 'json'
                    })
                    .then(response => {
                        if (response.data.code == '0') {
                            this.addresses[this.editing_address_index] = response.data.address;
                            this.is_show_edit = false;
                        } else if (response.data.code == '4101') {
                            location.href = '/login/?next=/addresses/';
                        }else if (response.data.code == '4007') {
                            this.error_mobile = true;
                        } else if (response.data.code == '5002') {
                            this.error_tel = true;
                        } else if (response.data.code == '5001') {
                            this.error_email = true;
                        } else { // 4003 5000 (以弹框的形式出现)
                            alert(response.data.errmsg);
                        }
                    })
                    .catch(error => {
                        alert(error.response);
                    })
                }
            }
        },
        // 删除地址
        delete_address(index){
            var url = this.host + '/addresses/' + this.addresses[index].id + '/';
            axios.delete(url, {
                headers: {
                    'X-CSRFToken':getCookie('csrftoken')
                },
                responseType: 'json'
            })
            .then(response => {
                if (response.data.code == '0') {
                    // 删除对应的标签
                    this.addresses.splice(index, 1);
                } else if (response.data.code == '4101') {
                    location.href = '/login/?next=/addresses/';
                }else {
                    alert(response.data.errmsg);
                }
            })
            .catch(error => {
                console.log(error.response);
            })
        },
        // 设置默认地址
        set_default(index){
            var url = this.host + '/addresses/' + this.addresses[index].id + '/default/';
            axios.put(url, {}, {
                headers: {
                    'X-CSRFToken':getCookie('csrftoken')
                },
                responseType: 'json'
            })
            .then(response => {
                if (response.data.code == '0') {
                    // 设置默认地址标签
                    this.default_address_id = this.addresses[index].id;
                } else if (response.data.code == '4101') {
                    location.href = '/login/?next=/addresses/';
                } else {
                    alert(response.data.errmsg);
                }
            })
            .catch(error => {
                console.log(error.response);
            })
        },
        // 设置地址title
        show_edit_title(index){
            this.edit_title_index = index;
        },
        // 取消保存地址title
        cancel_title(){
            this.edit_title_index = '';
            this.input_title = '';
        },
        // 保存地址title
        save_title(index){
            if (!this.input_title) {
                alert("请填写标题后再保存！");
            } else {
                var url = this.host + '/addresses/' + this.addresses[index].id + '/title/';
                axios.put(url, {
                        title: this.input_title
                    }, {
                        headers: {
                            'X-CSRFToken':getCookie('csrftoken')
                        },
                        responseType: 'json'
                    })
                    .then(response => {
                        if (response.data.code == '0') {
                            // 更新地址title
                            this.addresses[index].title = this.input_title;
                            this.cancel_title();
                        } else if (response.data.code == '4101') {
                            location.href = '/login/?next=/addresses/';
                        } else {
                            alert(response.data.errmsg);
                        }
                    })
                    .catch(error => {
                        console.log(error.response);
                    })
            }
        },
    }
});





// var now_site = null;
//
// var error_receiver = false;
// var error_place = false;
// var error_mobile = false;
// var error_tel = false;
// var error_email = false;
//
// var default_address_id;
// var destroy_address_id;
// var edit_address_id;
// var title_address_id;
// var now_title = null;
// var is_set_default = false; // 禁止设置默认地址的暴力操作
//
// $(function() {
//     // 新增收货地址弹框
//     var $addsite = $('.site_top_con a');
//     var $shutoff = $('.site_pop_title a');
//     var $reset = $('.info_reset');
//
//     // 新增收货地址点击事件
//     $addsite.click(function () {
//         count = $('.site_top_con').find('span b').html();
//     	if (count >= 20) {
//     		alert("超过地址数量上限");
//     	} else {
//     		$('.pop_con').show();
//     	}
//     });
//
//     $shutoff.click(function () {
//         $reset.click();
//     });
//
//     $reset.click(function () {
//         $('.pop_con').find('.site_pop_title h3').html('新增收货地址');
//         $('.pop_con').find('.info_submit').eq(0).val('新 增');
//         $('.pop_con').hide();
//     });
//
//     // 界面右侧标签点击事件：设为默认，删除，编辑
//     $('.right_content').delegate('a,span', 'click', function () {
//         var sHandler = $(this).prop('class');
//
//         // 设为默认
//         if (sHandler == 'set_default') {
//             // 获取要设为默认的地址的ID
//             if (is_set_default) {
//                 return;
//             }
//             is_set_default = true;
//             default_address_id = $(this).parent().attr('default_edit_address_id');
//             set_default_address($(this));
//         }
//
//         // 点击上面的编辑图标和下面的编辑文字
//         if (sHandler == 'edit_icon') {
//             var $pop = $('.pop_con');
//             $pop.find('.site_pop_title h3').html('编辑收货地址');
//             $pop.find('.info_submit').eq(0).val('确 定');
//
//             var $con = $(this).closest('.site_con');
//             var $b = $con.find('b');
//             var $input = $pop.find('input[type="text"]');
//             $input.eq(0).val($b.eq(0).html());
//             $input.eq(1).val($b.eq(2).html());
//             $input.eq(2).val($b.eq(3).html());
//             $input.eq(3).val($b.eq(4).html());
//             $input.eq(4).val($b.eq(5).html());
//             $pop.show();
//
//             // 获取要重新编辑地址的 ID
//             edit_address_id = $(this).parent().attr('default_edit_address_id');
//         }
//
//         // 删除
//         if (sHandler == 'del_site') {
//             now_site = $(this).closest('.site_con');
//
//             // 获取要删除的地址的ID
//             destroy_address_id = $(this).attr('destroy_address_id');
//             if (!destroy_address_id) {
//                 alert('无效的地址ID');
//                 return;
//             }
//             $('.pop_con2').show();
//         }
//
//         // 编辑标题
//         if(sHandler=='edit_title'){
//             now_title = $(this).prev();
//             var now_title_txt = now_title.html();
//             var $input = $('<input type="text" style="float:left" />');
//             var $that = $(this); // 点击的a标签
//             $input.val(now_title_txt);
//             now_title.remove();
//             $input.insertBefore($(this));
//             $input.focus(); // 默认为焦点
//
//             $input.blur(function(){
//                 title_address_id = $that.attr('title_address_id');
//                 edit_title($input, $that);
//             });
//         }
//
//     });
//
//     // 确定和取消弹框
//     var $shutconfirm = $('.confirm_pop_title a,.confirm_cancel');
//     var $confirm = $('.confirm_submit').eq(0);
//     $shutconfirm.click(function () {
//         $('.pop_con2').hide();
//         // 取消删除
//     });
//
//     // 确认删除
//     $confirm.click(function () {
//         destroy_address();
//     });
//
//     // 校验数据
//     $('.receiver').blur(function () {
//         check_receiver();
//     });
//
//     $('.place').blur(function () {
//         check_place();
//     });
//
//     $('.mobile').blur(function () {
//         check_mobile();
//     });
//
//     $('.tel').blur(function () {
//         check_tel();
//     });
//
//     $('.email').blur(function () {
//         check_email();
//     });
//
//     // 获取省级地区数据
//     get_areas();
//
//     // 选择了省份
//     $('.province').change(function () {
//         province_id = $(this).val();
//         get_city(province_id);
//     });
//
//     // 选择了城市
//     $('.city').change(function () {
//         city_id = $(this).val();
//         get_district(city_id);
//     });
// });
//
//
// function check_receiver() {
//     var receiver = $('.receiver').val();
//     if (!receiver) {
//         $('.receiver_error').html('请填写收货人');
//         error_receiver = true;
//     } else {
//         $('.receiver_error').empty();
//         error_receiver = false;
//     }
// }
//
// function check_place() {
//     var place = $('.place').val();
//     if (!place) {
//         $('.place_error').html('请填写详细地址');
//         error_place = true;
//     } else {
//         $('.place_error').empty();
//         error_place = false;
//     }
// }
//
// function check_mobile() {
//     var re = /^1[3-9]\d{9}$/;
//     var mobile = $('.mobile').val();
//
//     if (!re.test(mobile)) {
//         $('.mobile_error').html('手机号有误');
//         error_mobile = true;
//     } else {
//         $('.mobile_error').empty();
//         error_mobile = false;
//     }
// }
//
// function check_tel() {
//     var tel = $('.tel').val();
//     if (tel) {
//         var re = /^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$/;
//         if (!re.test(tel)) {
//             $('.tel_error').html('固定电话有误');
//             error_tel = true;
//         } else {
//             $('.tel_error').empty();
//             error_tel = false;
//         }
//     } else {
//         $('.tel_error').empty();
//         error_tel = false;
//     }
// }
//
// function check_email() {
// 		var email = $('.email').val();
// 		if (email) {
// 			var re = /^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$/;
// 			if (!re.test(email)) {
// 				$('.email_error').html('邮箱格式有误');
// 				error_email = true;
// 			} else {
// 				$('.email_error').empty();
// 				error_email = false;
// 			}
// 		} else {
// 		    $('.email_error').empty();
//             error_email = false;
//         }
// 	}
//
//
// // 获取省级地区数据
// function get_areas() {
// 	$.get('/areas/', function (response) {
// 		if (response.code == '0') {
// 			province_tag = $('.province');
// 			$.each(response.province_list, function (i,province) {
// 				province_tag.append('<option name="province" value="'+province.id+'">'+province.name+'</option>');
// 			});
// 		} else {
// 			console.log(response);
// 		}
//     });
// }
//
// // 获取城市数据
// function get_city(province_id) {
// 	if (province_id == 0) {
// 		// 禁止无效的地区选项
// 		city_tag = $('.city').empty().append('<option value="0">请选择</option>');
// 		$('.district').empty().append('<option value="0">请选择</option>');
// 		return;
// 	}
// 	$.get('/areas/' + province_id + '/', function (response) {
// 	    if (response.code == '0') {
// 	        city_tag = $('.city').empty().append('<option value="0">请选择</option>');
//             $('.district').empty().append('<option value="0">请选择</option>');
//             $.each(response.sub_data.subs, function (i, city) {
//                 city_tag.append('<option name="city" value="'+city.id+'">'+city.name+'</option>');
//             });
//         } else {
// 			console.log(response);
// 		}
// 	});
// }
//
// // 获取区县数据
// function get_district(city_id) {
// 	if (city_id == 0) {
// 		// 禁止无效的地区选项
// 		district_tag = $('.district').empty().append('<option value="0">请选择</option>');
// 		return;
// 	}
// 	$.get('/areas/' + city_id + '/', function (response) {
// 	    if (response.code == '0') {
//             district_tag = $('.district').empty().append('<option value="0">请选择</option>');
//             $.each(response.sub_data.subs, function (i, district) {
//                 district_tag.append('<option name="district" value="' + district.id + '">' + district.name + '</option>');
//             });
//         } else {
// 			console.log(response);
// 		}
// 	});
// }
//
//
// // 添加用户地址+编辑地址
// function add_user_address() {
//
//     check_receiver();
//     check_place();
//     check_mobile();
//     check_tel();
//     check_email();
//
//     if (error_receiver == false && error_place == false && error_mobile == false && error_tel == false && error_email == false) {
//
//         var receiver = $('.receiver').val();
//         var province_id = $('.province').val();
//         // var province = $('.province').find("option:selected").text();
//         var city_id = $('.city').val();
//         // var city = $('.city').find("option:selected").text();
//         var district_id = $('.district').val();
//         // var district = $('.district').find("option:selected").text();
//         var place = $('.place').val();
//         var mobile = $('.mobile').val();
//         var tel = $('.tel').val();
//         var email = $('.email').val();
//
//         var params = {
//             "receiver": receiver,
//             "province_id": province_id,
//             // "province": province,
//             "city_id": city_id,
//             // "city": city,
//             "district_id": district_id,
//             // "district": district,
//             "place": place,
//             "mobile": mobile,
//             "tel": tel,
//             "email": email
//         };
//
//         var url;
//         var method;
//         if (edit_address_id) {
//             url = '/addresses/' + edit_address_id + '/update/';
//             method = 'put';
//         } else {
//             url = '/addresses/create/';
//             method = 'post';
//         }
//
//         $.ajax({
//             url: url,
//             type: method,
//             data: JSON.stringify(params),
//             contentType: 'application/json',
//             headers: {'X-CSRFToken': getCookie('csrftoken')},
//             success: function (response) {
//                 if (response.code == '0') {
//                     location.reload();
//                 } else if (response.code == "4101") {
//                     // 用户未登录
//                     location.href = '/login/?next=/addresses/';
//                 } else {
//                     console.log(response);
//                     alert(response.errmsg);
//                 }
//             }
//         });
//     }
// }
//
//
// // 删除地址
// function destroy_address() {
//     var url = '/addresses/' + destroy_address_id + '/destroy/';
//     $.ajax({
//         url: url,
//         type: 'delete',
//         contentType: 'application/json',
//         headers: {'X-CSRFToken':getCookie('csrftoken')},
//         success:function (response) {
//             if (response.code == '0') {
//                 now_site.remove();
//                 $('.pop_con2').hide();
//             } else if (response.code == "4101") {
//                 // 用户未登录
//                 location.href = '/login/?next=/addresses/';
//             } else {
//                 console.log(response);
//                 alert(response.errmsg);
//             }
//         }
//     });
// }
//
//
// // 设置默认地址
// function set_default_address(obj) {
//     if (!default_address_id) {
//         alert('无效的地址ID');
//         return;
//     }
//
//     var url = '/addresses/' + default_address_id + '/default/';
//     $.ajax({
//         url: url,
//         type: 'put',
//         contentType: 'application/json',
//         headers: {'X-CSRFToken':getCookie('csrftoken')},
//         success:function (response) {
//             if (response.code == '0') {
//
//                 var $nowcon = $('.site_top_con').next();
//
//                 $nowcon.find('em').remove();
//                 var $set_default = $('<a href="javascript:;" class="set_default">设为默认</a>');
//                 $set_default.prependTo($nowcon.find('.down_btn'));
//
//                 var $con = obj.closest('.site_con');
//                 var $newem = $('<em>默认地址</em>');
//                 $newem.insertBefore($con.find('.del_site'));
//                 $con.insertAfter($('.site_top_con'));
//                 obj.remove();
//
//                 is_set_default = false;
//
//             } else if (response.code == "4101") {
//                 // 用户未登录
//                 location.href = '/login/?next=/addresses/';
//             } else {
//                 console.log(response);
//                 alert(response.errmsg);
//             }
//         }
//     });
// }
//
//
// // 编辑地址标题
// function edit_title(input_obj, a_obj) {
//     title = input_obj.val();
//
//     var params = {
//         'address_id':title_address_id,
//         'title':title
//     };
//
//     var url = '/addresses/' + title_address_id + '/title/';
//     $.ajax({
//         url: url,
//         type: 'put',
//         data: JSON.stringify(params),
//         contentType: 'application/json',
//         headers: {'X-CSRFToken':getCookie('csrftoken')},
//         success:function (response) {
//             if (response.code == '0') {
//
//                 now_title.html( input_obj.val() );
//                 input_obj.remove(); // $(this) 是新建的input
//                 now_title.insertBefore(a_obj); // 重新添加标题a标签
//
//             } else if (response.code == "4101") {
//                 // 用户未登录
//                 location.href = '/login/?next=/addresses/';
//             } else {
//                 alert(response.errmsg);
//             }
//         }
//     });
// }