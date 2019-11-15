using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebDT.Models
{
    public class User
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();
        public bool Insert(DangNhap entity)
        {
            try
            {
                _db.DangNhaps.Add(entity);
                _db.SaveChanges();
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
           
        }
        public DangNhap getById(string userName)
        {
            return _db.DangNhaps.SingleOrDefault(x => x.username == userName);
        }
        public int Login(string userName, string passWord )
        {
            var result = _db.DangNhaps.SingleOrDefault(x => x.username == userName);
            if (result == null)
            {
                return 0;
            }
            else
            {
                if (result.status == false)
                {
                    return -1;
                }
                else
                {
                    if (result.password == passWord)
                   
                            return 1;
                    
                    else
                        return -2;
                }
            }
        }
        public bool CheckUserName(string userName)
        {
            return _db.DangNhaps.Count(x => x.username == userName) > 0;
        }
        public bool CheckEmail(string email)
        {
            return _db.DangNhaps.Count(x => x.email == email) > 0;
        }


    }
}