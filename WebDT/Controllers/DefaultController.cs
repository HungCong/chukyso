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
    public class DefaultController : Controller
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();
        // GET: Default
        public ActionResult Index()
        {
            var model = _db.products.OrderBy(x => x.datebegin).ToList();
            return View(model);
        }
        public ActionResult getHinhChieu()
        {
            var v = from t in _db.HinhChieux
                    where t.hide == true
                    orderby t.order ascending
                    select t;
            return PartialView(v.ToList());
        }
        public ActionResult getSPMoi()
        {
            var v = from t in _db.products
                    where t.hdie == true
                    orderby t.datebegin  descending
                    select t;
            return PartialView(v.ToList());
        }
        
        public ActionResult getGioiThieu()
        {
            ViewBag.meta = "gioi-thieu";
            var v = from t in _db.GioiThieux
                    where t.meta == "gioi-thieu"
                    orderby t.order ascending
                    select t;
            return PartialView(v.ToList());
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>

 
        public ActionResult getCategory()
        {
            ViewBag.meta = "san-pham";
            var v = from t in _db.categories
                    where t.hide == true
                    orderby t.datebegin ascending
                    select t;
            return PartialView(v.ToList());            
        }

      

       
        public ActionResult getKhuyenMai()
        {
            var v = from t in _db.products
                    where t.hdie == true && t.price != null
                    orderby t.datebegin ascending
                    select t;
            return PartialView(v.ToList());
        }
        public ActionResult getXemNhanhSP()
        {
            var list = from sp in _db.products
                       where sp.hdie == true
                       select sp;
            return PartialView(list.ToList());
        }
        
        
    }
}