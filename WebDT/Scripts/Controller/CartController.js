/// <reference path="cartController.js" />
var cart = {
    init: function () {
        cart.regEvents();
    },
    regEvents: function () {
        $('#btnContinue').off('click').on('click', function () {
            window.location.href = "/trang-chu";
        });

        $('#btnPayment').off('click').on('click', function () {
            window.location.href = "/thanh-toan";
        });

        $('.btn-delete').off('click').on('click', function (e) {
            e.preventDefault();
            $.ajax({
                data: { id: $(this).data("id") },
                url: '/GioHang/Delete',
                dataType: 'json',
                type: 'POST',
                success: function (res) {
                    if (res.status == true) {
                        window.location.href = "/gio-hang";
                    }
                }
            })
        });

        $('.btn-edit').off('click').on('click', function (e) {
            var listbook = $('.txt_quantity');
            var cartList = [];
            $.each(listbook, function (i, item) {
                cartList.push({
                    Quantity: $(item).val(),
                    Product: {
                        id: $(item).data('id')
                    }
                });
            });

            //Phương thức Ajax dùng để đẩy lên Controller
            $.ajax({
                url: '/GioHang/Edit',
                data: { cartModel: JSON.stringify(cartList) },
                dataType: 'Json',
                type: 'POST',
                success: function (res) {
                    if (res.status == true) {
                        window.location.href = "/gio-hang";
                    }
                }
            });
        });
    }
}
cart.init();