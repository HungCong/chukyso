using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebDT.Models;

namespace WebDT.Areas.admin.Controllers
{
    public class AccountPaymentController : Controller
    {
        private WebMayTinhEntities db = new WebMayTinhEntities();
        // GET: admin/AccountPayment
        public ActionResult Index()
        {
            var model = db.AccountPayments.ToList();
            return View(model);
        }
    }
}