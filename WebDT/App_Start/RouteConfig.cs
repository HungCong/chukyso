using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace WebDT
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute(
               name: "thanh toán lỗi",
               url: "thanh-toan-loi",
               defaults: new { controller = "AccountPayment", action = "ErrorPayment_Confirm", id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" }
           );

            routes.MapRoute(
               name: "thanh toán thành công",
               url: "thanh-toan-thanh-cong",
               defaults: new { controller = "AccountPayment", action = "SuccessPayment", id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" }
           );

            routes.MapRoute(
               name: "Lỗi đăng nhập thanh toán",
               url: "loi-dang-nhap",
               defaults: new { controller = "AccountPayment", action = "ErrorPayment", id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" }
           );

            routes.MapRoute(
               name: "Lỗi đký thanh toán",
               url: "loi-dang-ky",
               defaults: new { controller = "AccountPayment", action = "ErrorResgister", id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" }
           );

            routes.MapRoute(
                name: "Xác nhận thanh toán",
                url: "xac-nhan-thanh-toan",
                defaults: new { controller = "AccountPayment", action = "Payment", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.Controllers" }
            );

            routes.MapRoute(
                name: "Hoàn thành đăng ký thanh toán",
                url: "dang-ky-thanh-cong",
                defaults: new { controller = "AccountPayment", action = "success", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.Controllers" }
            );

            //Đăng ký thanh toán online
            routes.MapRoute(
                name: "đăng ký thanh toán",
                url: "dang-ky-thanh-toan",
                defaults: new { Controller = "AccountPayment", Action = "RegisterPayment", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            //Tìm kiếm nâng cao
            routes.MapRoute(
                name: "Tìm kiếm nâng cao",
                url: "loc-san-pham",
                defaults: new { Controller = "Product", Action = "Index", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            //thanh toán online
            routes.MapRoute(
                name: "Payment online",
                url: "mua-ngay/{id}",
                defaults: new { Controller = "GioHang", Action = "PaymentOnline", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            routes.MapRoute(
                 name: "Giới thiệu",
                 url: "gioi-thieu",
                 defaults: new { Controller = "Home", Action = "About", id = UrlParameter.Optional },
                 namespaces: new[] { "WebDT.controllers" });

          

            routes.MapRoute("SanPham", "{type}/{meta}",
                new { controller = "ProductMenu", action = "Index", meta = UrlParameter.Optional },
                new RouteValueDictionary
                {
                    {"type","san-pham" }
                },
                namespaces: new[] { "WebDT.Controllers" });

            routes.MapRoute(
                name: "Cửa hàng",
                url: "cua-hang",
                defaults: new { Controller = "Home", Action = "Index", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });
            routes.MapRoute(
                name: "Cửa hàng khuyến mãi",
                url: "cua-hang-khuyen-mai",
                defaults: new { Controller = "Cuahangkhuyenmai", Action = "Index", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });
            routes.MapRoute(
                name: "Kiểm tra đơn hàng",
                url: "Kiem-tra-don-hang",
                defaults: new { Controller = "TaiKhoan", Action = "DanhSachHoaDon", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });

            routes.MapRoute(
                name: "Thông tin sản phẩm",
                url: "san-pham/{meta}/{id}",
                defaults: new { Controller = "Product", Action = "Detail", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });

            routes.MapRoute(
                name: "Giỏ hàng",
                url: "gio-hang",
                defaults: new { Controller = "GioHang", Action = "Index", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });
          routes.MapRoute(
               name: "Thêm vào giỏ",
               url: "them-gio-hang",
               defaults: new { controller = "GioHang", action = "ThemVaoGio",  id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" });
            routes.MapRoute(
               name: "Thanh toán",
               url: "thanh-toan",
               defaults: new { controller = "GioHang", action = "ThanhToan", id = UrlParameter.Optional },
               namespaces: new[] { "WebDT.Controllers" });
            routes.MapRoute(
                name: "Hoàn thành",
                url: "hoan-thanh",
                defaults: new { controller = "GioHang", action = "Success", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.Controllers" }
            );

            routes.MapRoute(
              name: "Liên hệ",
              url: "lien-he",
              defaults: new { Controller = "Home", Action = "Contact", id = UrlParameter.Optional },
              namespaces: new[] { "WebDT.controllers" });

            routes.MapRoute(
                    name: "Gửi Thành công",
                    url: "thanh-cong",
                    defaults: new { controller = "Home", action = "Success", id = UrlParameter.Optional },
                    namespaces: new[] { "WebDT.Controllers" }
                );

            routes.MapRoute(
                name: "Tin tức",
                url: "tin-tuc-su-kien",
                defaults: new { Controller = "Home", Action = "TinTuc", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            routes.MapRoute(
                name: "DangNhap",
                url: "dang-nhap",
                defaults: new { Controller = "TaiKhoan", Action = "DangNhap", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            routes.MapRoute(
                name: "DangKy",
                url: "dang-ky",
                defaults: new { Controller = "TaiKhoan", Action = "DangKy", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });


            routes.MapRoute(
                  name: "Sản phẩm vừa xem gần đây",
                  url: "xem-gan-day",
                  defaults: new { Controller = "DaXem", Action = "Index", id = UrlParameter.Optional },
                  namespaces: new[] { "WebDT.controllers" });

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Default", action = "Index", id = UrlParameter.Optional },
                namespaces: new[] { "WebDT.controllers" });
                
        }
    }
}
