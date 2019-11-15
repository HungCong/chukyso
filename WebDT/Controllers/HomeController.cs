using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebDT.Models;
using PagedList;
using PagedList.Mvc;

namespace WebDT.Controllers
{
    public class HomeController : Controller
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();

    
        public ActionResult Index(int ? page)
        {
            int pageNumber = (page ?? 1);
            int pageSize = 12;
            var v = from t in _db.products
                    where t.meta != null
                    orderby t.order ascending
                    select t;

            return PartialView(v.ToPagedList(pageNumber, pageSize));
            

        }
    
        
        public ActionResult About()
        {
            ViewBag.Message = "Your contact page12.";

            return View();
        }
            public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page13.";

            return View();
        }
        
        public ActionResult Success()
        {
            return View();
        }
        public ActionResult TinTuc()
        {
            ViewBag.Message = "Your contact page32.";

            return View();
        }

        public ActionResult DangNhap()
        {
            ViewBag.Message = "Your contact page33.";

            return View();
        }
    }
}