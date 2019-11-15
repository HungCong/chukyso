using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebDT.Models
{
    public class ProductModel
    {
        public int id { get; set; }
        public string name { get; set; }
        public Nullable<double> price { get; set; }
        public Nullable<double> newprice { get; set; }
        public string img { get; set; }
        public string description { get; set; }
        public string meta { get; set; }
        public Nullable<bool> hdie { get; set; }
        public Nullable<int> order { get; set; }
        public Nullable<System.DateTime> datebegin { get; set; }
        public Nullable<int> categoryid { get; set; }
        public Nullable<int> SoLuong { get; set; }

        public virtual category category { get; set; }
    }
}