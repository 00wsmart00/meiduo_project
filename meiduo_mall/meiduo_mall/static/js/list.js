var vm = new Vue({
    el: '#app',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host,
        cart_total_count: 0, // 购物车总数量
        carts: [], // 购物车数据,
		hot_skus: [],
        category_id: category_id,
    },
    mounted(){
        // 获取购物车数据
        this.get_carts();

		// 获取热销商品数据
        this.get_hot_goods();
    },
    methods: {
        // 获取购物车数据
        get_carts(){
        	var url = this.host + '/carts/simple/';
            axios.get(url, {
                    responseType: 'json',
                })
                .then(response => {
                    this.carts = response.data.cart_skus;
                    this.cart_total_count = 0;
                    for(var i=0;i<this.carts.length;i++){
                        if (this.carts[i].name.length>25){
                            this.carts[i].name = this.carts[i].name.substring(0, 25) + '...';
                        }
                        this.cart_total_count += this.carts[i].count;
                    }
                })
                .catch(error => {
                    console.log(error.response);
                })
        },
    	// 获取热销商品数据
        get_hot_goods(){
        	var url = this.host + '/hot/'+ this.category_id +'/';
            axios.get(url, {
                    responseType: 'json'
                })
                .then(response => {
                    this.hot_skus = response.data.hot_skus;
                    for(var i=0; i<this.hot_skus.length; i++){
                        this.hot_skus[i].url = '/goods/' + this.hot_skus[i].id + '.html';
                    }
                })
                .catch(error => {
                    console.log(error.response);
                })
        }
    }
});









// $(function () {
//
//     // 获取并展示购物车数据
//     get_cart();
//
//     // 获取热销商品
// 	var category_id = $('.breadcrumb').attr('category_id');
// 	get_hot_sku(category_id);
// });