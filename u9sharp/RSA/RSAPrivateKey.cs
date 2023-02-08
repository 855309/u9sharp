using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp.RSA
{
    public class RSAPrivateKey
    {
        public BigInteger modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient;
        public BigInteger ctf; // ekok(p - 1, q - 1)

        // modulus 2 nin kuvveti olmalı bazen 1023 filan oluyo o yüzden onu kontrol edip yapalım
        private void SetupPrimes(int bits)
        {
            prime1 = Prime.random_prime(bits / 2);
            prime2 = Prime.random_prime(bits / 2);

            modulus = prime1 * prime2;
        }

        // bits -> Modulus bit sayısı
        public RSAPrivateKey(int bits)
        {
            SetupPrimes(bits);
            while (Helper.BitSize(modulus) != bits)
            {
                SetupPrimes(bits);
            }

            ctf = (prime1 - 1) * (prime2 - 1) / BigInteger.GreatestCommonDivisor(prime1 - 1, prime2 - 1); // ekok(p - 1, q - 1)

            publicExponent = 65537; // hep böyle kullanılıyomuş

            // d = e^-1 (mod ctf) yani
            // de = 1 (mod ctf) ise ebob(e, ctf) = 1 olduğundan
            // e*x + y*ctf = 1 olur burdaki katsayı da d olur.
            // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
            privateExponent = Helper.ModInverse(publicExponent, ctf);

            exponent1 = privateExponent % (prime1 - 1);
            exponent2 = privateExponent % (prime2 - 1);
            coefficient = Helper.ModInverse(prime2, prime1);
        }

        public RSAPrivateKey(BigInteger p1, BigInteger p2)
        {
            prime1 = p1;
            prime2 = p2;
            modulus = prime1 * prime2;
            ctf = (prime1 - 1) * (prime2 - 1) / BigInteger.GreatestCommonDivisor(prime1 - 1, prime2 - 1); // ekok(p - 1, q - 1)
            publicExponent = 65537;
            privateExponent = Helper.ModInverse(publicExponent, ctf);
            exponent1 = privateExponent % (prime1 - 1);
            exponent2 = privateExponent % (prime2 - 1);
            coefficient = Helper.ModInverse(prime2, prime1);
        }

        public RSAPrivateKey(string path)
        {
            Import(path);
        }

        public RSAPublicKey GetPublicKey()
        {
            return new RSAPublicKey(this);
        }

        public byte[] ASN1Encode()
        {
            /*
             *  RSA Key formatı (ASN.1): 
             *  
             *  Full:
             *  SEQUENCE {
             *      INTEGER, -- 0'dı openssl pem dosyasında
             *      SEQ.{
             *          obj. id (1.2.840.113549.1.1.1 -> rsaEncryption)
             *          NULL
             *      },
             *      Octet str.
             *  }
             *  
             *  Octet str. yerine:
             *  RSAPrivateKey::= SEQUENCE {
             *      version          Version,
             *      modulus          INTEGER,  -- n
             *      publicExponent   INTEGER,  -- e
             *      privateExponent  INTEGER,  -- d
             *      prime1           INTEGER,  -- p
             *      prime2           INTEGER,  -- q
             *      exponent1        INTEGER,  -- d mod(p - 1)
             *      exponent2        INTEGER,  -- d mod(q - 1)
             *      coefficient      INTEGER,  -- q^-1 mod p
             *      otherPrimeInfos  OtherPrimeInfos OPTIONAL -- burası yok version 0 olduğundan
             *  }
             */

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                writer.WriteInteger(0);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // rsaEncryption
                    writer.WriteNull();
                }

                using (writer.PushOctetString())
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteInteger(0); // version
                        writer.WriteInteger(modulus); // modulus
                        writer.WriteInteger(publicExponent); // publicExponent
                        writer.WriteInteger(privateExponent); // privateExponent
                        writer.WriteInteger(prime1); // prime1
                        writer.WriteInteger(prime2); // prime2
                        writer.WriteInteger(exponent1); // exponent1  d mod p-1
                        writer.WriteInteger(exponent2); // exponent2  d mod q-1
                        writer.WriteInteger(coefficient); // coefficient q^-1 mod p
                    }
                }
            }

            return writer.Encode();
        }

        public string GetRandomArt()
        {
            long bits = Helper.BitSize(modulus);
            string title = $"RSA {string.Concat(Enumerable.Repeat(" ", 5 - bits.ToString().Length)) + bits.ToString()}";

            return RandomArt.Generate(Helper.HashMD5(ASN1Encode()), title);
        }

        public void Export(string path)
        {
            string data = Convert.ToBase64String(ASN1Encode());

            List<string> lines = new List<string>();

            lines.Add("-----BEGIN PRIVATE KEY-----");

            // data 64 uzunlukta satırlara bölünücek
            int div = Math.DivRem(data.Length, 64, out _);
            lines.AddRange(Enumerable.Range(0, div + 1).Select(i =>
            {
                return i == div ? data.Substring(i * 64) : data.Substring(i * 64, 64);
            }));

            lines.Add("-----END PRIVATE KEY-----");

            string text = string.Empty;
            foreach (string line in lines)
            {
                if (line.Trim() != "")
                {
                    text += line + "\r\n";
                }
            }

            File.WriteAllText(path, text);
        }

        public bool Verify()
        {
            RSAPrivateKey verpk = new RSAPrivateKey(prime1, prime2);
            return 
                Prime.check_prime_prob(prime1)
                && Prime.check_prime_prob(prime2)
                && modulus == verpk.modulus
                && publicExponent == verpk.publicExponent
                && privateExponent == verpk.privateExponent
                && exponent1 == verpk.exponent1
                && exponent2 == verpk.exponent2
                && coefficient == verpk.coefficient;
        }

        public void Import(string path, bool verify = true)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("File not found.", path);
            }

            List<string> txtdata = File.ReadAllLines(path).Select(str => str.Trim()).ToList();
            byte[] asndata = Convert.FromBase64String(
                string.Concat(txtdata.GetRange(1, txtdata.Count() - 2)
            ));

            /*
             *  Full:
             *  SEQUENCE {
             *      INTEGER, -- 0'dı openssl pem dosyasında
             *      SEQ.{
             *          obj. id (1.2.840.113549.1.1.1 -> rsaEncryption)
             *          NULL
             *      },
             *      Octet str.
             *  }
             */

            var reader = new AsnReader(asndata, AsnEncodingRules.DER).ReadSequence();

            reader.ReadInteger(); // 0

            var seq = reader.ReadSequence();
            if (seq.ReadObjectIdentifier() != "1.2.840.113549.1.1.1")
            {
                Console.WriteLine("Key format is not PKCS#1.");
                return;
            }
            seq.ReadNull();

            byte[] oct = reader.ReadOctetString();

            var octreader = new AsnReader(oct, AsnEncodingRules.DER);
            var octseq = octreader.ReadSequence();

            /*
             *      version          Version,
             *      modulus          INTEGER,  -- n
             *      publicExponent   INTEGER,  -- e
             *      privateExponent  INTEGER,  -- d
             *      prime1           INTEGER,  -- p
             *      prime2           INTEGER,  -- q
             *      exponent1        INTEGER,  -- d mod(p - 1)
             *      exponent2        INTEGER,  -- d mod(q - 1)
             *      coefficient      INTEGER,  -- q^-1 mod p
             */

            if (octseq.ReadInteger() != 0)
            {
                Console.WriteLine("Anything other than PKCS Version 0 is not supported.");
                return;
            }

            modulus = octseq.ReadInteger();
            publicExponent = octseq.ReadInteger();
            privateExponent = octseq.ReadInteger();
            prime1 = octseq.ReadInteger();
            prime2 = octseq.ReadInteger();
            exponent1 = octseq.ReadInteger();
            exponent2 = octseq.ReadInteger();
            coefficient = octseq.ReadInteger();

            if (verify)
            {
                if (!Prime.check_prime_prob(prime1))
                {
                    Console.WriteLine("{0} is not prime.", prime1);
                }
                if (!Prime.check_prime_prob(prime2))
                {
                    Console.WriteLine("{0} is not prime.", prime2);
                }

                if (!this.Verify())
                {
                    throw new Exception("Incorrect key.");
                }
            }
        }
    }
}
