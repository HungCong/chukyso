using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace WebDT.Models
{
    public class SignalModel
    {
        private WebMayTinhEntities db = new WebMayTinhEntities();
        public List<BigInteger> TaoKhoa()
        {
            BigInteger p = new BigInteger();
            BigInteger q = new BigInteger();
            BigInteger t = new BigInteger();
            Random random = new Random();
            BigInteger temp = new BigInteger();
            
            t = random.Next(11, 97);

            while (!CHECK_SNT(t))
            {
                t = random.Next(11, 97);
            }

            q = random.Next(1001, 9997);

            while (!CHECK_SNT(q))
            {
                q = random.Next(1001, 9997);
            }

            p = q * t * t * temp + 1;
            while (!CHECK_SNT(p))
            {
                temp = random.Next(11, 97);
                p = q * t * t * temp + 1;
            }

            //Tạo khóa riêng tư
            BigInteger X = privateKey(p, q);

            List<BigInteger> Khoa = new List<BigInteger>(); // khai báo mảng chứa khóa 1,2 PriKey 3,4 PubKey

           
            Khoa.Add(X);//Lưu khóa riêng tư
            Khoa.Add(p); //so_p
            Khoa.Add(t); //số mũ công khai so_t
            Khoa.Add(q); //so_q
            return Khoa;
        }

        //Tạo khóa riêng tư
        public BigInteger privateKey(BigInteger p, BigInteger q)
        {
            BigInteger X = new BigInteger();
            BigInteger anpha = new BigInteger();
            Random random = new Random();

            //anpha.genRandomBits(511, random); //random biến anpha với 511 bit
            anpha = random.Next(1001, 9997);
            X = BigInteger.ModPow(anpha, (p - 1) / q, p);  //khóa riêng tư: x = anpha^[(p-1)/p] mod p
            while (X == 1)
            {
                //anpha.genRandomBits(511, random);
                //X = anpha.ModPow((p - 1) / q, p);
                anpha = random.Next(1001, 9997);
                X = BigInteger.ModPow(anpha, (p - 1) / q, p); //khóa riêng tư: x = anpha^[(p-1)/p] mod p
            }
            return X;
        }
        
        //Tạo khóa công khai
        public BigInteger publicKey(BigInteger priKey, BigInteger p, BigInteger t)
        {
            BigInteger Y = new BigInteger();
            //Y = priKey.modPow(t, p);
            Y = BigInteger.ModPow(priKey, t, p);
            return Y;
        }


        //Kiểm tra khóa công khai có bị trùng k
        public bool CheckKeyPublic(long n, long e)
        {
            var model = db.AccountPayments.Where(x => x.so_n == n && x.so_e == e).ToList();
            if (model.Count > 0)
                return false;
            return true;
        }

        // tim uoc chung lon nhat
        public int UOC_CHUNG_LON_NHAT(long x, long y)
        {
            int uoc = 1;
            for (int i = 1; i <= x; i++)
            {
                if (x % i == 0 && y % i == 0) uoc = i;
            }
            return uoc;
        }

        // kiem tra so nguyen to
        public bool CHECK_SNT(BigInteger n)
        {
            bool flag = true;
            if (n < 2) return false;
            for (int i = 2; i <= Math.Sqrt((double)n); i++)
            {
                if (n % i == 0 && n != i)
                {
                    flag = false;
                    break;
                }
                else
                    flag = true;
               
            }
            return flag;
        }

        string key = "A!9HHhi%XjjYY4YP2@Nob009X*1234567890!@#$%^&*()14344*";

        public string Encrypt_MD5(string text)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] textBytes = UTF8Encoding.UTF8.GetBytes(text);
                        byte[] bytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                        return Convert.ToBase64String(bytes, 0, bytes.Length);
                    }
                }
            }
        }

        public string Decrypt_MD5(string cipher)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    using (var transform = tdes.CreateDecryptor())
                    {
                        byte[] cipherBytes = Convert.FromBase64String(cipher);
                        byte[] bytes = transform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                        return UTF8Encoding.UTF8.GetString(bytes);
                    }
                }
            }
        }

        //hàm băm tin
        public byte[] hash(string xau)
        {
            byte[] textBytes = Encoding.Default.GetBytes(xau);
            try
            {
                MD5CryptoServiceProvider cryptHandler;
                cryptHandler = new MD5CryptoServiceProvider();
                byte[] hash = cryptHandler.ComputeHash(textBytes);

                return hash;
            }
            catch
            {
                throw;
            }
        }

        //Tạo chữ ký
        public List<BigInteger> SinhChuKy(BigInteger p, BigInteger t, BigInteger q, BigInteger pri_key, string encrypt_message)
        {
            BigInteger K = new BigInteger();
            BigInteger Z = new BigInteger();
            BigInteger S = new BigInteger();
            BigInteger E = new BigInteger();
            BigInteger R = new BigInteger();
            BigInteger Y_inv = new BigInteger();
            BigInteger X_inv = new BigInteger();
            BigInteger u = new BigInteger();
            BigInteger v = new BigInteger();
            BigInteger tmp1 = new BigInteger();
            BigInteger tmp2 = new BigInteger();

            Random random = new Random();

            BigInteger gamma = new BigInteger();

            //gamma.genRandomBits(511, random);
            //K = gamma.modPow((p - 1) / q, p);

            gamma = random.Next(1001, 9997);
            K = BigInteger.ModPow(gamma, (p - 1) / q, p);  
            while (K == 1)
            {
                //gamma.genRandomBits(511, random);
                //K = gamma.modPow((p - 1) / q, p);

                gamma = random.Next(1001, 9997);
                K = BigInteger.ModPow(gamma, (p - 1) / q, p);
            }
            //Z = K.modPow(t, p);
            Z = BigInteger.ModPow(K, t, p); 
            E = BigInteger.Parse(Decrypt_MD5(encrypt_message));
            
            BigInteger X = pri_key;
            BigInteger Y = publicKey(X, p, t);

            //X_inv = X.modInverse(p);
            X_inv = modInverse(X, p);

            //Y_inv = Y.modInverse(q);
            Y_inv = modInverse(Y, q);
            tmp1 = Y_inv * Z % q;

            //tmp2 = X_inv.modPow(tmp1, p);
            tmp2 = BigInteger.ModPow(X_inv, tmp1, p); 
            tmp1 = K * tmp2 % p;

            //tmp2 = (Y_inv * E + 1).modInverse(q);
            tmp2 = modInverse(Y_inv * E + 1, q);

            //v = tmp1.modPow(tmp2, p);
            v = BigInteger.ModPow(tmp1, tmp2, p); 
            tmp1 = Y_inv * E % q;
            tmp2 = Y_inv * Z % q;

            //u = v.modPow(tmp1, p) * X.modPow(tmp2, p) % p;
            u = BigInteger.ModPow(v, tmp1, p) * BigInteger.ModPow(X, tmp2, p) % p;
            
            //R = u.modPow(t, p);
            R = BigInteger.ModPow(u, t, p);

            //S = v.modPow(t, p);
            S = BigInteger.ModPow(v, t, p);  

            List<BigInteger> lst = new List<BigInteger>();
            lst.Add(R);
            lst.Add(S);
            return lst;
        }

        public BigInteger HamBam(string hash)
        {
            System.Text.UTF8Encoding gbyte = new System.Text.UTF8Encoding();
            byte[] bytes1 = gbyte.GetBytes(hash);
            SHA1CryptoServiceProvider SHS = new SHA1CryptoServiceProvider();
            byte[] hashBytes = SHS.ComputeHash(bytes1);
            BigInteger res = new BigInteger(hashBytes);
            return res;
        }


        public long TINHA(long a, long b, long p)
        {
            long ret = 1;
            a %= p;
            b %= p - 1;
            while (b > 0) //vòng lặp phân tích b thành cơ số 2
            {
                if (b % 2 > 0)  //ở vị trí có số 1 thì nhân với a^(2^i) tương ứng. Tất cả các phép nhân đều có phép mod p theo sau.
                    ret = ret * a % p;
                a = a * a % p;  //tính tiếp a^(2^(i+1)), a^1 -> a^2 -> a^4 -> a^8 -> a^16 v.v...
                b /= 2;
            }
            return (long)ret;
        }

        //Nghịch đảo mod
        BigInteger modInverse(BigInteger a, BigInteger m)
        {
            BigInteger g = gcd(a, m);
            if (g != 1)
                return 0;
            else
            {
                return power(a, m - 2, m);
            }
        }

        public BigInteger power(BigInteger x, BigInteger y, BigInteger m)
        {
            if (y == 0)
                return 1;

            BigInteger p = power(x, y / 2, m) % m;
            p = (p * p) % m;

            if (y % 2 == 0)
                return p;
            else
                return (x * p) % m;
        }

        public BigInteger gcd(BigInteger a, BigInteger b)
        {
            if (a == 0)
                return b;
            return gcd(b % a, a);
        }
    }
}

/*
 ReRadom://Radom để chọn lại khóa
            //Radom để chọn khóa
            Random r = new Random();
            long x = r.Next(1001, 9997);
            long y = r.Next(1001, 9997);
            while (CHECK_SNT(x) == false || CHECK_SNT(y) == false)
            {
                Random rr = new Random();
                x = rr.Next(1001, 9997);
                y = rr.Next(1001, 9997);
            }


            List<long> Khoa = new List<long>(); // khai báo mảng chứa khóa 1,2 PriKey 3,4 PubKey

            long N = x * y; //Tính số hàm modulo của hệ thống 
            long phi = (x - 1) * (y - 1); //Tính giá trị hàm số Ơ-le
            long E = 0;
            for (long i = 17; i < phi; i++) //Tìm số nguyên tố cùng nhau của E vs phi trong khoảng từ 1 <= E <= phi
            {
                if (UOC_CHUNG_LON_NHAT(i, phi) == 1)
                {
                    E = i;

                    break;
                }
            }

            //Kiểm tra có lặp khóa bí mật không.
            if (!CheckKeyPublic(N, E))
                goto ReRadom;

            int t; // 1 < t < phi(n)
                   //tínhkhóa công khai

            //D = e^t mod n


            Random rr = new Random();
            t = rr.Next(1, (int)phi);


            Double soD = Math.Pow(E, t) % N;

            //long k = nd(soE, phi);
            //Tính khóa giải mã D sao cho D*E = 1(mod phi(n))
            //    long k = 1;
            //while (((phi * k + 1) % E != 0))
            //{ k++; }

            //long soD = (phi * k + 1) / E; //tính số D

            Khoa.Add((long)soD);
            Khoa.Add(N);
            Khoa.Add(E);
            Khoa.Add(N);
            return Khoa;
     */
