using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp.RSA
{
    public class RSAEngine
    {
        public RSAPrivateKey? privateKey;
        public RSAPublicKey? publicKey;

        public RSAEngine(RSAPrivateKey key) 
        {
            this.privateKey = key;
            this.publicKey = key.GetPublicKey();
        }

        public RSAEngine(RSAPublicKey publicKey)
        { 
            this.privateKey = null;
            this.publicKey = publicKey;
        }

        public RSAEngine(RSAPrivateKey privateKey, RSAPublicKey publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;

            RSAPublicKey vpb = privateKey.GetPublicKey();
            if (vpb.modulus != publicKey.modulus || vpb.publicExponent != publicKey.publicExponent)
            {
                Console.WriteLine("Incompatible public/private key.");
            }
        }

        public RSAEngine()
        {
            this.privateKey = null;
            this.publicKey = null;
        }

        private BigInteger RSAEP(BigInteger m, BigInteger publicExponent, BigInteger modulus)
        {
            BigInteger pow = BigInteger.ModPow(m, publicExponent, modulus);
            return (pow < 0) ? (pow + modulus) : pow;
        }

        private BigInteger RSADP(BigInteger c, BigInteger privateExponent, BigInteger modulus)
        {
            BigInteger pow = BigInteger.ModPow(c, privateExponent, modulus);
            return (pow < 0) ? (pow + modulus) : pow;
        }

        private byte[] RSAOAEPEncrypt(byte[] data, string? label)
        {
            if (publicKey == null) { return new byte[0]; }

            /* ----- EME-OAEP Encoding ----- */
            string L = label ?? string.Empty;
            int mLen = data.Length;

            int k = (int)(Helper.BitSize(publicKey.modulus) / 8);
            byte zero = 0;

            // SHA1, hLen = 20 (bytes), 160 (bits)
            Func<byte[], byte[]> hash_func = Helper.HashSHA1;

            byte[] lHash = hash_func(Encoding.UTF8.GetBytes(L));
            int hLen = lHash.Length;

            if (mLen > k - (2 * hLen) - 2)
            {
                Console.WriteLine("message too long.");
                return new byte[0];
            }

            byte[] PS = Enumerable.Repeat(zero, k - mLen - (2 * hLen) - 2).ToArray();

            List<byte> DB = new List<byte>(lHash);
            DB.AddRange(PS);
            DB.Add(0x01);
            DB.AddRange(data);

            byte[] seed = new byte[hLen];
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            rnd.GetBytes(seed);

            byte[] dbMask = Masking.MGF1(seed, k - hLen - 1, hash_func);
            byte[] maskedDB = Helper.XOR(DB.ToArray(), dbMask);

            byte[] seedMask = Masking.MGF1(maskedDB, hLen, hash_func);
            byte[] maskedSeed = Helper.XOR(seed, seedMask);

            List<byte> EMLst = new List<byte>(){ 0x0 };
            EMLst.AddRange(maskedSeed);
            EMLst.AddRange(maskedDB);

            byte[] EM = EMLst.ToArray();
            Array.Reverse(EM); // big endian yap (baştaki sıfır datayı moddan daha büyük yapıyo)

            /* ----- RSA Encryption ----- */
            BigInteger m = new BigInteger(EM, isUnsigned: true);
            BigInteger c = RSAEP(m, publicKey.publicExponent, publicKey.modulus);
            
            /*if (m > publicKey.modulus)
            {
                //throw new Exception();
                Console.WriteLine("------ --- -- --- ----- !!!!!!!!!! --- - -------- -- ----------- --");
            }*/

            /*Console.WriteLine("Msg: {0}", m);
            Console.WriteLine("Cph: {0}", c);*/
            byte[] sx = Helper.I2OSP(c, k);
            return sx;
        }

        public byte[] Encrypt(byte[] data, string? label, RSAEncryptionScheme scheme)
        {
            if (publicKey == null)
            {
                Console.WriteLine("error");
                return new byte[0];
            }

            if (scheme == RSAEncryptionScheme.OAEP)
            {
                return RSAOAEPEncrypt(data, label);
            }

            return new byte[0];
        }

        private byte[] DecryptionError() { Console.WriteLine("decryption error."); return new byte[0]; }

        private byte[] RSAOAEPDecrypt(byte[] cipher, string? label)
        {
            if (privateKey == null) { return new byte[0]; }

            int k = (int)(Helper.BitSize(privateKey.modulus) / 8);
            // Console.WriteLine(k);
            /* ----- RSA Decryption ----- */
            BigInteger c = new BigInteger(cipher, isUnsigned: true);
            BigInteger m = RSADP(c, privateKey.privateExponent, privateKey.modulus);

            /*Console.WriteLine("D Cph: {0}", c);
            Console.WriteLine("D Msg: {0}", m);*/

            byte[] EM = Helper.I2OSP(m, k);
            Array.Reverse(EM); // little endian yap (EM[0] == 0x0)

            /* ----- EME-OAEP Decoding ----- */
            string L = label ?? string.Empty;

            // SHA1, hLen = 20 (bytes), 160 (bits)
            Func<byte[], byte[]> hash_func = Helper.HashSHA1;

            byte[] lHash = hash_func(Encoding.UTF8.GetBytes(L));
            int hLen = lHash.Length;

            if (cipher.Length != k || k < (2 * hLen) + 2)
            {
                /*Console.WriteLine("C Len: {0}", cipher.Length);
                Console.WriteLine("K Len: {0}", k);*/
                return DecryptionError();
            }

            /*   EM = Y || maskedSeed || maskedDB   */
            //   Y -> 0x0
            //   maskedSeed -> hLen
            //   maskedDB -> k - hLen - 1

            byte Y = EM[0];
            byte[] maskedSeed = new byte[hLen];
            byte[] maskedDB = new byte[k - hLen - 1];

            if (Y != 0)
            {
                return DecryptionError();
            }

            Array.Copy(EM, 1, maskedSeed, 0, hLen); // 1 <-> 1 + hLen (1 -> Y)
            Array.Copy(EM, 1 + hLen, maskedDB, 0, k - hLen - 1); // 1 + hLen <-> son

            byte[] seedMask = Masking.MGF1(maskedDB, hLen, hash_func);
            byte[] seed = Helper.XOR(maskedSeed, seedMask);

            byte[] dbMask = Masking.MGF1(seed, k - hLen - 1, hash_func);
            byte[] DB = Helper.XOR(maskedDB, dbMask);

            /*   DB = lHash' || PS || 0x01 || M   */

            byte[] newlHash = new byte[hLen];
            Array.Copy(DB, newlHash, hLen);

            if (!lHash.SequenceEqual(newlHash))
            {
                return DecryptionError();
            }

            // skip 0
            int ind = 0x0;
            while (DB[hLen + ind] == 0x0)
            {
                ind++;
            }

            if (DB[hLen + ind] != 0x01)
            {
                return DecryptionError();
            }
            ind++; // 0x01

            int mLen = DB.Length - hLen - ind;
            byte[] data = new byte[mLen];
            Array.Copy(DB, hLen + ind, data, 0, mLen);

            return data;
        }

        public byte[] Decrypt(byte[] data, string? label, RSAEncryptionScheme scheme)
        {
            if (privateKey == null)
            {
                Console.WriteLine("error");
                return new byte[0];
            }

            if (scheme == RSAEncryptionScheme.OAEP)
            {
                return RSAOAEPDecrypt(data, label);
            }

            return new byte[0];
        }
    }
}
