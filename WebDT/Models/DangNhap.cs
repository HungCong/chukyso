//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace WebDT.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class DangNhap
    {
        public int id { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string name { get; set; }
        public string address { get; set; }
        public string email { get; set; }
        public string phone { get; set; }
        public Nullable<bool> status { get; set; }
        public Nullable<System.DateTime> buyLastDate { get; set; }
        public Nullable<int> countOrder { get; set; }
        public Nullable<double> amountSpent { get; set; }
        public Nullable<double> accountNumber { get; set; }
    }
}
