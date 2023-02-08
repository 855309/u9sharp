using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp.RSA
{
    public class RSAPublicKey
    {
        public BigInteger modulus, publicExponent;
        public RSAPublicKey(RSAPrivateKey pk)
        {
            modulus = pk.modulus;
            publicExponent = pk.publicExponent;
        }

        public RSAPublicKey(BigInteger mod, BigInteger pubExp)
        {
            modulus = mod;
            publicExponent = pubExp;
        }

        public RSAPublicKey(string path)
        {
            Import(path);
        }

        /*public byte[] Encrypt(byte[] data)
        {
            BigInteger dt = new BigInteger(data);
        }*/

        public byte[] ASN1Encode()
        {
            /*
             *  RSA Pub. Key formatı (ASN.1): 
             *  
             *  Full:
             *  SEQUENCE {
             *      SEQ.{
             *          obj. id (1.2.840.113549.1.1.1 -> rsaEncryption)
             *          NULL
             *      },
             *      Bit str.
             *  }
             *  
             *  Bit str. yerine:
             *  RSAPublicKey::= SEQUENCE {
             *      modulus          INTEGER,  -- n
             *      publicExponent   INTEGER   -- e
             *  }
            */

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // rsaEncryption
                    writer.WriteNull();
                }

                var bitwriter = new AsnWriter(AsnEncodingRules.DER);
                using (bitwriter.PushSequence())
                {
                    bitwriter.WriteInteger(modulus); // modulus
                    bitwriter.WriteInteger(publicExponent); // publicExponent
                }

                writer.WriteBitString(bitwriter.Encode());
            }

            return writer.Encode();
        }

        public string GetRandomArt()
        {
            long bits = Helper.BitSize(modulus);
            string title = $"RSA{bits}";

            return RandomArt.Generate(Helper.HashMD5(ASN1Encode()), title);
        }

        public void Export(string path)
        {
            string data = Convert.ToBase64String(ASN1Encode());

            List<string> lines = new List<string>();

            lines.Add("-----BEGIN PUBLIC KEY-----");

            // data 64 uzunlukta satırlara bölünücek
            int div = Math.DivRem(data.Length, 64, out _);
            lines.AddRange(Enumerable.Range(0, div + 1).Select(i =>
            {
                return i == div ? data.Substring(i * 64) : data.Substring(i * 64, 64);
            }));

            lines.Add("-----END PUBLIC KEY-----");

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

        public void Import(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Dosya bulunamadı.", path);
            }

            List<string> txtdata = File.ReadAllLines(path).Select(str => str.Trim()).ToList();
            byte[] asndata = Convert.FromBase64String(
                string.Concat(txtdata.GetRange(1, txtdata.Count() - 2)
            ));

            var reader = new AsnReader(asndata, AsnEncodingRules.DER).ReadSequence();

            var seq = reader.ReadSequence();
            if (seq.ReadObjectIdentifier() != "1.2.840.113549.1.1.1")
            {
                Console.WriteLine("PKCS#1 harici key.");
                return;
            }
            seq.ReadNull();

            byte[] bitstr = reader.ReadBitString(out _);

            var bitreader = new AsnReader(bitstr, AsnEncodingRules.DER);
            var bitseq = bitreader.ReadSequence();

            /*
             *      modulus          INTEGER,  -- n
             *      publicExponent   INTEGER   -- e
             */

            modulus = bitseq.ReadInteger();
            publicExponent = bitseq.ReadInteger();
        }
    }
}
