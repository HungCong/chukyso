using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Web;
using System.Web.Mvc;
using WebDT.Models;

namespace WebDT.Controllers
{
    public class AccountPaymentController : Controller
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();
        SignalModel sig = new SignalModel();
        private const string CartSession = "CartSession";
        // GET: AccountPayment
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult RegisterPayment()
        {
            return View();
        }

        [HttpPost]
        public ActionResult RegisterPayment(double? accountNumber, string accountName, string phone)
        {
            
            var res = _db.AccountPayments.Where(x => x.accountNumber == accountNumber).ToList();
            if(res.Count > 0)
            {
                return Redirect("/loi-dang-ky");
            }
            else
            {
                
                List<BigInteger> khoa = sig.TaoKhoa(); 

                var acc = new AccountPayment();
                acc.accountNumber = accountNumber;
                acc.accountName = accountName;
                acc.accountBalance = 100000000;//Cho số dư tài khoản là 100tr
                acc.phone = phone;
                //Tạo khóa công khai
                acc.so_p = khoa[1].ToString();
                acc.so_t = khoa[2].ToString();
                acc.so_q = khoa[3].ToString();

                //Tạo khóa bí mật và mã hóa
                acc.pri_key = sig.Encrypt_MD5(khoa[0].ToString());

                acc.status = true;
                _db.AccountPayments.Add(acc);
                _db.SaveChanges();
                return Redirect("/dang-ky-thanh-cong");
            }
           
        }
        [HttpGet]
        public ActionResult Payment()
        {
            var model = Session[CartSession];
            return View(model);
        }
        
        [HttpPost]
        public ActionResult Payment(double? accountNumber, string accountName)
        {
            var model = _db.AccountPayments.Where(x => x.accountNumber == accountNumber && x.accountName == accountName).SingleOrDefault();
            Session["AccountPayment"] = (AccountPayment)model;
            if (model == null)
            {
                return Redirect("/loi-dang-nhap");
            }
            else
            {
                return Redirect("/xac-nhan-thanh-toan");
            }

        }

        [HttpPost]
        public ActionResult ConfirmPayment(double? accountNumber, double? total)
        {
            List<CartItem> lstCart = (List<CartItem>)Session[CartSession];
            var acc = _db.AccountPayments.Where(x => x.accountNumber == accountNumber).SingleOrDefault();

            //Chuyển thành chuỗi để băm
            string str_cart = acc.accountName + " " + acc.accountNumber + " " + acc.accountBalance;
            foreach(var item in lstCart)
            {
                str_cart += item.Product;
                str_cart += item.Quantity;
            }

            //Băm chuối
            BigInteger arrayhash = sig.HamBam(str_cart);
           

            //mã hóa chuỗi
            string encrypt_message = sig.Encrypt_MD5(arrayhash.ToString());

            BigInteger pri_key = BigInteger.Parse(sig.Decrypt_MD5(acc.pri_key));

            //Sinh chữ ký
            List<BigInteger> lstRS = sig.SinhChuKy(BigInteger.Parse(acc.so_p), BigInteger.Parse(acc.so_t), BigInteger.Parse(acc.so_q), pri_key, encrypt_message);
            
            //sinh khóa công khai
            BigInteger pub_key = sig.publicKey(pri_key, BigInteger.Parse(acc.so_p.Trim()), BigInteger.Parse(acc.so_t.Trim()));

            //Gửi xác thực chữ ký
            var res = new AccountPaymentDAO().KiemTraChuKy(encrypt_message, lstRS[0], lstRS[1], pub_key, BigInteger.Parse(acc.so_p.Trim()));
            if (!res)//Bản tin đã bị thay đổi
            {
                return Redirect("/thanh-toan-loi");
            }
            else
            {
                //Lưu hóa đơn
                var order = new GioHang();
                order.TenKhachHang = acc.accountName;
                order.NgayTao = DateTime.Now;
                order.NoiDung = "Ok";
                order.PayFormat = 2;
                order.SDTKhachHang = acc.phone;
                order.status = true;
                try
                {
                    _db.GioHangs.Add(order);
                    _db.SaveChanges();

                    //Lưu vào chi tiết hóa đơn
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
                    return Redirect("/thanh-toan-loi");
                }

                //Trừ tiền trong tài khoản thanh toán
                acc.accountBalance -= total;

                //Cộng tiền cho admin
                var admin = _db.AccountPayments.Find(1);
                admin.accountBalance += total;
                _db.SaveChanges();

                return Redirect("/thanh-toan-thanh-cong");
            }

        }

        public ActionResult success()
        {
            return View();
        }

        public ActionResult ErrorResgister()
        {
            return View();
        }
       
        public ActionResult ErrorPayment()
        {
            return View();
        }

        public ActionResult SuccessPayment()
        {
            return View();
        }

        public ActionResult ErrorPayment_Confirm()
        {
            return View();
        }
    }
}