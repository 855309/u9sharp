using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp
{
    public class Prime
    {
        public static int round_num = 10; // yeterli olur heralde

        public static BigInteger NextBigInteger(RandomNumberGenerator rng, BigInteger minValue, BigInteger maxValue)
        {
            if (minValue > maxValue) throw new ArgumentException();
            if (minValue == maxValue) return minValue;
            BigInteger zeroBasedUpperBound = maxValue - 1 - minValue; // Inclusive
            Debug.Assert(zeroBasedUpperBound.Sign >= 0);
            byte[] bytes = zeroBasedUpperBound.ToByteArray();
            Debug.Assert(bytes.Length > 0);
            Debug.Assert((bytes[bytes.Length - 1] & 0b10000000) == 0);

            // Search for the most significant non-zero bit
            byte lastByteMask = 0b11111111;
            for (byte mask = 0b10000000; mask > 0; mask >>= 1, lastByteMask >>= 1)
            {
                if ((bytes[bytes.Length - 1] & mask) == mask) break; // We found it
            }

            while (true)
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] &= lastByteMask;
                var result = new BigInteger(bytes);
                Debug.Assert(result.Sign >= 0);
                if (result <= zeroBasedUpperBound) return result + minValue;
            }
        }

        public static BigInteger random_bigint(int bits)
        {
            /*byte[] data = new byte[bits];

            random.NextBytes(data);

            return new BigInteger(data);*/
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            return NextBigInteger(rng, BigInteger.Pow(2, bits - 1), BigInteger.Pow(2, bits) - 1);
        }

        public static bool check_prime_prob(BigInteger num)
        {
            // Miller-Rabin (prob.)

            // bir s > 0 için n - 1 = (2^s)*d sağlayan d tek > 0 sayısını bul
            int s = 1;
            BigInteger d = (num - 1) / 2;

            while (d % 2 != 1)
            {
                s++;
                d = d >> 1;
            }

            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            int k = round_num; // round sayısı
            for (BigInteger round = 0; round < k; round++)
            {
                BigInteger a = NextBigInteger(rng, 2, num - 2);
                BigInteger x = BigInteger.ModPow(a, d, num);

                for (int m = 0; m < s; m++)
                {
                    BigInteger y = BigInteger.ModPow(x, 2, num);
                    if (y == 1 && x != 1 && x != num - 1)
                    {
                        return false;
                    }

                    x = y;
                }

                if (x != 1)
                {
                    return false;
                }
            }

            return true;
        }

        public static bool check_prime(BigInteger num)
        {
            // Miller-Rabin (det.)

            // bir s > 0 için n - 1 = (2^s)*d sağlayan d tek > 0 sayısını bul
            int s = 1;
            BigInteger d = (num - 1) / 2;

            while (d % 2 != 1)
            {
                s++;
                d = d >> 1;
            }

            Random random = new Random();

            for (BigInteger a = 2; a <= BigInteger.Min(num - 2, 2*BigInteger.Pow((int)Math.Floor(BigInteger.Log(num)), 2)); a++)
            {
                // BigInteger a = NextBigInteger(random, 2, num - 2);
                BigInteger x = BigInteger.ModPow(a, d, num);

                for (int m = 0; m < s; m++)
                {
                    BigInteger y = BigInteger.ModPow(x, 2, num);
                    if (y == 1 && x != 1 && x != num - 1)
                    {
                        return false;
                    }

                    x = y;
                }

                if (x != 1)
                {
                    return false;
                }
            }

            return true;
        }

        public static BigInteger random_prime(int bits)
        {
            BigInteger p = random_bigint(bits);
            while (!check_prime_prob(p))
            {
                p = random_bigint(bits);
            }

            return p;
        }
    }
}
