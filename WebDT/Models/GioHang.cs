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
    
    public partial class GioHang
    {
        public int id { get; set; }
        public Nullable<System.DateTime> NgayTao { get; set; }
        public string IDKhachHang { get; set; }
        public string TenKhachHang { get; set; }
        public string SDTKhachHang { get; set; }
        public string DiaChi { get; set; }
        public string Email { get; set; }
        public string NoiDung { get; set; }
        public Nullable<bool> status { get; set; }
        public Nullable<int> PayFormat { get; set; }
    }
}
