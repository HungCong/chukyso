using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using WebDT.Models;

namespace WebDT.Controllers
{
    public class GioHangController : Controller
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();
        private const string CartSession = "CartSession";

        // GET: GioHang
        public ActionResult Index()
        {

            var cart = Session[CartSession];
            var list = new List<CartItem>();
            if (cart != null)
            {
                list = (List<CartItem>)cart;
            }
            return View(list);


        }
        public ActionResult ThemVaoGio(int productId, int quantity)
        {
            var cart = Session[CartSession];
            if (cart != null)
            {
                var list = (List<CartItem>)cart;
                if (list.Exists(x => x.Product.id == productId))
                {
                    foreach (var item in list)
                    {
                        if (item.Product.id == productId)
                        {
                            item.Quantity += quantity;
                        }
                    }
                }
                else
                {
                    var item = new CartItem();
                    item.Product = _db.products.Find(productId);
                    item.Quantity = quantity;
                    list.Add(item);
                }
                Session[CartSession] = list;
            }
            else
            {
                var item = new CartItem();
                item.Product = _db.products.Find(productId);
                item.Quantity = quantity;
                var list = new List<CartItem>();
                list.Add(item);


                Session[CartSession] = list;
            }
            return RedirectToAction("");
        }
        public JsonResult Delete(int id)
        {
            var sessionCart = (List<CartItem>)Session[CartSession];
            sessionCart.RemoveAll(x => x.Product.id == id);
            Session[CartSession] = sessionCart;
            return Json(new
            {
                status = true
            });
        }

        //Sửa số lượng
        public JsonResult Edit(string cartModel)
        {
            var JsonCart = new JavaScriptSerializer().Deserialize<List<CartItem>>(cartModel);
            var cartSec = (List<CartItem>)Session[CartSession];

            foreach (var item in cartSec)
            {
                var jsonItem = JsonCart.SingleOrDefault(x => x.Product.id == item.Product.id);
                if (jsonItem != null)
                {
                    item.Quantity = jsonItem.Quantity;
                }
            }

            Session[CartSession] = cartSec;
            return Json(new
            {
                status = true
            });
        }

        public ActionResult ThanhToan()
        {
            var cart = Session[CartSession];
            var list = new List<CartItem>();
            if (cart != null)
            {
                list = (List<CartItem>)cart;
            }
            return View(list);
        }

        [HttpPost]
        public ActionResult ThanhToan(int? productId, string totalPrice, string tenkhachhang, string sdt, string diachi, string email, string noidung)
        {

            var order = new GioHang();
            order.NgayTao = DateTime.Now;
            order.IDKhachHang = Session["UserName"].ToString();  
            order.DiaChi = diachi;
            order.Email = email;
            order.TenKhachHang = tenkhachhang;
            order.SDTKhachHang = sdt;
            order.NoiDung = noidung;
            order.status = true;
            if(Session[CartSession] == null)
            {
                var item = new CartItem();
                item.Product = _db.products.Find(productId);
                item.Quantity = 1;
                var list = new List<CartItem>();
                list.Add(item);

                Session[CartSession] = list;
            }

            //Lưu ngày đặt hàng, thêm tổng đơn hàng, thêm tổng tiền đã chi
            var user = _db.DangNhaps.Single(x => x.name == tenkhachhang);
            user.buyLastDate = DateTime.Now;
            user.countOrder += 1;
            user.amountSpent += float.Parse(totalPrice);
            _db.SaveChanges();
            try
            {
                _db.GioHangs.Add(order);
                _db.SaveChanges();

                var cart = (List<CartItem>)Session[CartSession];
                foreach (var i in cart)
                {
                    var orderDetail = new ChiTietGioHang();
                    orderDetail.IDSanPham = i.Product.id;
                    orderDetail.IDGioHang = order.id;
                    if (i.Product.newprice != null)
                    {
                      
                        orderDetail.Tien = i.Product.newprice * i.Quantity;
                    }
                    else
                    {
                        orderDetail.Tien = i.Product.price * i.Quantity;
                    }
                    
                    orderDetail.SoLuong = i.Quantity;

                    _db.ChiTietGioHangs.Add(orderDetail);
                    _db.SaveChanges();
                }
                //thanh toán thành công thì cho giỏ hàng bằng null
                Session[CartSession] = null;
            }
            catch
            {
                return Redirect("/loi-thanh-toan");
            }
            ViewBag.Alert = "Bạn vừa đặt hàng thành công.";
            return Redirect("/hoan-thanh");
        }
        public ActionResult Success()
        {
            
            return View();
            
        }
        public PartialViewResult HeaderCart()
        {
            var cart = Session[CartSession];
            var list = new List<CartItem>();
            if (cart != null)
            {
                list = (List<CartItem>)cart;
            }
            return PartialView(list);
        }

        //Thanh toán online
        public ActionResult PaymentOnline(long id)
        {
            if(@Session["ten"] == null)
            {
                return Redirect("/dang-nhap");
            }
            else
            {
                var v = _db.products.SingleOrDefault(x => x.id == id);
                ViewBag.PaymentOnline = v;
                return View();
            }
        }

    }
}