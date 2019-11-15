using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebDT.Areas.admin.Models;
using WebDT.Models;

namespace WebDT.Areas.admin.Controllers
{
    public class HoaDonController : Controller
    {
        private WebMayTinhEntities db = new WebMayTinhEntities();
        // GET: admin/HoaDon
        public ActionResult Index()
        {
            var model = from gh in db.GioHangs
                        join ct in db.ChiTietGioHangs on gh.id equals ct.IDGioHang
                        where gh.status == true
                        select new HoaDon
                        {
                            gioHangId = gh.id,
                            TenKhachHang = gh.TenKhachHang,
                            DiaChi = gh.DiaChi,
                            SDTKhachHang = gh.SDTKhachHang,
                            Email = gh.Email,
                            NgayTao = gh.NgayTao,
                            PayFormat = gh.PayFormat
                        };
            return View(model.Distinct().ToList());
        }

        public ActionResult DetailOrder(int gioHangId)
        {
            var khachhang = db.GioHangs.Find(gioHangId);
            ViewBag.TenKhachHang = khachhang.TenKhachHang;

            var model = from pr in db.products
                        join ct in db.ChiTietGioHangs on pr.id equals ct.IDSanPham
                        where ct.IDGioHang == gioHangId
                        select new HoaDon
                        {
                            name = pr.name,
                            img = pr.img,
                            Tien = pr.price,
                            SoLuong = ct.SoLuong
                        };
            ViewBag.gioHangID = gioHangId;
            return View(model.Distinct().ToList());
        }

        public JsonResult ProcessOrder(int id)
        {
            var giohang = db.GioHangs.Find(id);
            giohang.status = false;
            db.SaveChanges();
            return Json(new
            {
                status = true
            });
        }
    }
}