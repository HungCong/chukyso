using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Web;

namespace WebDT.Models
{
    public class AccountPaymentDAO
    {
        WebMayTinhEntities _db = new WebMayTinhEntities();
        SignalModel sig = new SignalModel();


        //Xác thực chữ ký 
        public int CheckSignal(string message, string signal, long so_n, long so_e)
        {
            List<long> Mang1 = new List<long>();
            List<long> Mang2 = new List<long>();
            
            //Giải mã bản tin thành hàm băm tạo ra bản tóm lược 1
            string decrypt_message = sig.Decrypt_MD5(message);

            //Xác thực chữ ký
            string[] chuoi = signal.Split(' ');
            for (int i = 0; i < chuoi.Length; i ++)
            {
                if (chuoi[i] == "")
                    continue;
                Mang1.Add(long.Parse(chuoi[i]));
            }

            //Xác thực chữ ký
            foreach (long i in Mang1)
            {
                long tam;

                //Giải mã chữ ký số cùng với khóa công khai và tạo ra bản tóm lược 2
                tam = sig.TINHA(i, so_e, so_n);
                Mang2.Add(tam);
            }

            //Chuyển thành chuỗi để so sánh
            string Decrypt_signal = String.Join("", Mang2);

            int k = 0;
            if(decrypt_message.Length == Decrypt_signal.Length)
            {
                for(int i = 0; i < decrypt_message.Length; i ++)
                {
                    if (Decrypt_signal[i] != decrypt_message[i])
                    {
                        k++;
                        break;
                    }
                }
            }
            else
            {
                k++;
            }

            if (k == 0)
                return 1; //Bản tin đc bảo toàn
            else
                return 0;//Bản tin đã bị thay đôi
        }

        //Xác thực chữ ký số, thuật toán khai căn
        public bool KiemTraChuKy(string encrypt_message, BigInteger R, BigInteger S, BigInteger Y, BigInteger p)
        {
            BigInteger A = new BigInteger();
            BigInteger B = new BigInteger();
            BigInteger E2 = new BigInteger();
            BigInteger Z2 = new BigInteger();
            BigInteger tmp3 = new BigInteger();
            BigInteger tmp4 = new BigInteger();

            E2 = BigInteger.Parse(sig.Decrypt_MD5(encrypt_message));
            //A = R.modPow(Y, p);
            A = BigInteger.ModPow(R, Y, p);  
            Z2 = (R * S) % p;
            //tmp3 = S.modPow(E2, p);
            tmp3 = BigInteger.ModPow(S, E2, p);
            //tmp4 = Y.modPow(Z2, p);
            tmp4 = BigInteger.ModPow(Y, Z2, p);     
            B = ( tmp3 * tmp4 ) % p;

            if (A == B)
                return true;
            else
                return false;
        }
    }
}