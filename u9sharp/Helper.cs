using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp
{
    public class Helper
    {
        // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
        public static (BigInteger, BigInteger, BigInteger) ExtendedGcd(BigInteger a, BigInteger b)
        {
            (BigInteger old_s, BigInteger s) = (1, 0);
            (BigInteger old_r, BigInteger r) = (a, b);
            
            BigInteger bezout_t;

            while (r != 0)
            {
                BigInteger quot = BigInteger.DivRem(old_r, r, out _);
                (old_r, r) = (r, old_r - (quot * r));
                (old_s, s) = (s, old_s - (quot * s));
            }

            if (b != 0)
            {
                bezout_t = BigInteger.DivRem(old_r - (old_s * a), b, out _);
            }
            else
            {
                bezout_t = 0;
            }

            return (old_r, old_s, bezout_t);
        }

        public static BigInteger ModInverse(BigInteger a, BigInteger b) 
        {
            (BigInteger t, BigInteger newt) = (0, 1);
            (BigInteger r, BigInteger newr) = (b, a);

            while (newr != 0)
            {
                BigInteger quot = BigInteger.DivRem(r, newr, out _);
                (t, newt) = (newt, t - (quot * newt));
                (r, newr) = (newr, r - (quot * newr));
            }

            if (r > 1)
            {
                throw new Exception("Tersi yok.");
            }

            if (t < 0)
            {
                t += b;
            }

            return t;
        }

        public static byte[] HashMD5(byte[] data) // 128 bit
        {
            return MD5.Create().ComputeHash(data);
        }

        public static byte[] HashSHA1(byte[] data) // 160 bit
        {
            return SHA1.Create().ComputeHash(data);
        }

        public static byte[] HashSHA256(byte[] data) // 160 bit
        {
            return SHA256.Create().ComputeHash(data);
        }

        /*// https://www.cryptrec.go.jp/cryptrec_03_spec_cypherlist_files/PDF/pkcs-1v2-12.pdf
        // I2OSP: 4.1
        public static byte[] I2OSP(BigInteger x, int size)
        {
            byte[] array = x.ToByteArray(); // rsa dayken byte[] alan fonk. kullan, 0ları sil

            // veya:
            // long byt_l = x.GetByteCount();
            long byt_l = (int)Math.Ceiling((double)x.GetBitLength() / (double)8);

            byte[] s_array = new byte[byt_l];
            Array.Copy(array, s_array, byt_l);
            return I2OSP(s_array, size);
        }

        public static byte[] I2OSP(byte[] array, int size)
        {
            byte zero = 0;

            List<byte> zs = new List<byte>(array);
            zs.AddRange(Enumerable.Repeat(zero, size - array.Length).ToList());

            return zs.ToArray();
        }*/

        /*
         def i2osp(x, xLen):
        if x >= 256**xLen:
            raise ValueError("integer too large")
        digits = []

        while x:
            digits.append(int(x % 256))
            x //= 256
        for i in range(xLen - len(digits)):
            digits.append(0)
        return digits[::-1]
         
         */

        public static int BitSize(BigInteger bits)
        {
            int size = 0;

            for (; bits != 0; bits >>= 1)
                size++;

            return size;
        }

        public static byte[] I2OSP(BigInteger x, int size) // TODO: Baştan yaz düzelt
        {
            int bytesize = BitSize(x) / 8;
            int bsize = BitSize(x);

            if (bytesize > size)
            {
                Console.WriteLine("BI Size: {0}", bytesize);
                Console.WriteLine("Ac Size: {0}", size);
                throw new OverflowException();
            }

            List<byte> bytes = new List<byte>(Enumerable.Repeat((byte)0x0, size));

            BigInteger ci = x;
            for (int j = 0; j < size; j++)
            {
                bytes[j] = (byte)(int)(ci % 256);
                ci /= 256;
            }

            // bytes.Reverse();
            return bytes.ToArray();
        }

        /*public static byte[] I2OSP(BigInteger x, int size)
        {
            byte[] array = x.ToByteArray();
            // Array.Reverse(array, 0, array.Length);
            return I2OSP(array, size);
        }

        public static byte[] I2OSP(byte[] x, int size)
        {
            byte[] result = new byte[size];
            Buffer.BlockCopy(x, 0, result, (result.Length - x.Length), x.Length);
            return result;
        }

        // 0 ları sil*/
        public static byte[] BITrim(BigInteger x)
        {
            byte[] array = x.ToByteArray();
            if (array[array.Length - 1] == 0x00)
            {
                return BITrim(x, 0x00);
            }
            else
            {
                return BITrim(x, 255);
            }
        }

        public static byte[] BITrim(BigInteger x, byte trim)
        {
            byte[] n_array = x.ToByteArray();

            // artık baştaki 0 lar oldu
            Array.Reverse(n_array, 0, n_array.Length);

            int trim_ind = 0;
            while (n_array[trim_ind] == trim)
            {
                trim_ind++;
            }

            byte[] array = new List<byte>(n_array).GetRange(trim_ind, n_array.Length - trim_ind).ToArray();
            Array.Reverse(array, 0, array.Length);

            return array;
        }

        public static byte[] XOR(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) { throw new Exception("xor için uzunluklar aynı değil."); }

            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                r[i] = (byte)(a[i] ^ b[i]);
            }

            return r;
        }
    }
}
