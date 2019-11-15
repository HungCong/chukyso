using Facebook;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using WebDT.Models;

namespace WebDT.Controllers
{
    public class TaiKhoanController : Controller
    {
        //jk
        WebMayTinhEntities _db = new WebMayTinhEntities();
        SignalModel sig = new SignalModel();

        // GET: TaiKhoan
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult DangKy()
        {

            return View();
        }
        [HttpPost]
        public ActionResult DangKy(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var us = new User();
                if (us.CheckUserName(model.username))
                {
                    ViewBag.Success = "Tên đăng nhập đã tồn tại!";
                }
                //else if (us.CheckEmail(model.email))
                //{
                //    ViewBag.Success = "Email đã tồn tại!";
                //}
                else
                {
                    var user = new DangNhap();
                    user.username = model.username;
                    user.password = model.password;
                    user.name = model.name;
                    user.accountNumber = model.accountNumber;
                    user.countOrder = 0;
                    user.amountSpent = 0;
                    user.status = true;

                    var acc = new AccountPayment();
                    acc.accountNumber = model.accountNumber;
                    acc.accountName = model.name.ToUpper();
                    acc.accountBalance = 100000000;

                    //Tạo khóa công khai
                    List<BigInteger> khoa = sig.TaoKhoa();
                    acc.so_p = khoa[1].ToString().Trim();
                    acc.so_t = khoa[2].ToString().Trim();
                    acc.so_q = khoa[3].ToString().Trim();

                    //Tạo khóa bí mật và mã hóa
                    acc.pri_key = sig.Encrypt_MD5(khoa[0].ToString());

                    acc.status = true;
                    _db.AccountPayments.Add(acc);
                    _db.SaveChanges();

                    var result = us.Insert(user);
                    if (result)
                    {
                        
                        ViewBag.Success = "Đăng ký thành công";
                        model = new RegisterModel();
                        return Redirect("/dang-nhap");
                    }
                    else
                    {
                        ViewBag.Success = "Đăng ký không thành công!";
                    }
                }
            }
            return View(model);
        }
        [HttpGet]
        public ActionResult DangNhap()
        {
            return View();
        }
        [HttpPost]
        public ActionResult DangNhap(ModelLogin model , String username )
        {
            if (ModelState.IsValid)
            {
               
                var ad = new User();
                var result = ad.Login(model.UserName, model.Password);
                var obj = _db.DangNhaps.Where(a=> a.username.Equals(username)).FirstOrDefault();

                if (result == 1)
                {
                    var user = ad.getById(model.UserName);
                    var userSession = new UserLogin();
                    userSession.UserName = user.username;                 
                    userSession.UserID = user.id;               
                    Session["UserName"] = model.UserName.ToString();
                    Session["ten"] = obj.name.ToString();
                    Session["admin"] =  obj.username.Trim();
                    //Session["User"] = obj.Quyenuser;
                    //Session["phone"] = obj.phone.ToString();
                    //Session["DiaChi"] = obj.address.ToString();
                    //Session["Email"] = obj.email.ToString();
                    Session["accountNumber"] = obj.accountNumber.ToString();

                    //var listCredential = ad.GetListCredential(model.UserName);
                    //Session.Add(CommonConstants.SESSION_CREDENTIALS, listCredential);
                    Session.Add(CommonConstants.USER_SESSION, userSession);
                    //var t = 'admin';
                   if (Session["admin"].ToString() == "admin")
                    {
                        return Redirect("http://localhost:54398/admin");
    
                    }
                    //else
                    //if( Session["User"]!=null)
                    //{
                    //    return Redirect("http://localhost:54398/admin");
                        
                    //}
                   else
                    {
                        return RedirectToAction("Index", "Default");
                    }
                   
                }
                else if (result == 0)
                {
                    ModelState.AddModelError("", "Tài khoảng không tồn tại!");
                }
                else if (result == -1)
                {
                    ModelState.AddModelError("", "Tài khoảng đang bị khóa!");
                }
                else if (result == -2)
                {
                    ModelState.AddModelError("", "Mật khẩu không đúng!");
                }
                else
                {
                    ModelState.AddModelError("", "Đăng nhập không thành công!");
                }
            }
            return View(model);

        }

        public ActionResult Logout()
        {
            Session.Abandon();
            return RedirectToAction("Index", "Home");
        }
        

        public ActionResult QuyenMatKhau(int? id)
        {

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            DangNhap TaiKhoan = _db.DangNhaps.Find(id);
            if (TaiKhoan == null)
            {
                return HttpNotFound();
            }
            return View(TaiKhoan);
        }
      

        //Danh sách hóa đơn đã đặt hàng của khách hàng.
        public ActionResult DanhSachHoaDon()
        {
           
            string user = Session["UserName"].ToString();
            List<DsSP> models = null;
            if (!string.IsNullOrEmpty(user)) //IsNullOrEmpty là cho biết chuỗi đã chỉ định là null hay rỗng
            {
                models = (from sp in _db.products
                          join chitietgh in _db.ChiTietGioHangs on sp.id equals chitietgh.IDSanPham
                          join giohangs in _db.GioHangs on chitietgh.IDGioHang equals giohangs.id
                          join taikhoankh in _db.DangNhaps on giohangs.IDKhachHang equals taikhoankh.username
                          where giohangs.IDKhachHang == user
                          select new DsSP()
                          {                            
                              TaiKhoan = taikhoankh.username,
                              Tensp = sp.name,
                              Hinh = sp.img,
                              Tien = chitietgh.Tien,
                              SoLuong = chitietgh.SoLuong,
                              NgayDat = giohangs.NgayTao,
                          }).ToList();
            }
            return View(models);
        }       
    }
}

