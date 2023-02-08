using System.Security.Cryptography;
using u9sharp.RSA;

namespace u9sharp.Tests
{
    [TestFixture]
    public class RSATests
    {
        private RSAEngine _engine;
        private RandomNumberGenerator _rng;
        private int _keysize = 512;

        [SetUp]
        public void Setup()
        {
            // _engine = new RSAEngine();
            _rng = RandomNumberGenerator.Create();
        }

        [Test]
        [Retry(5)]
        public void KeyExportImportVerification()
        {
            string prv_tmpFile = Path.GetTempFileName();
            string pub_tmpFile = Path.GetTempFileName();

            RSAPrivateKey privateKey = new RSAPrivateKey(_keysize);
            RSAPublicKey publicKey = privateKey.GetPublicKey();
            privateKey.Export(prv_tmpFile);
            publicKey.Export(pub_tmpFile);

            RSAPrivateKey imp_privateKey = new RSAPrivateKey(prv_tmpFile);
            RSAPublicKey imp_publicKey = new RSAPublicKey(pub_tmpFile);

            Assert.That(privateKey.prime1, Is.EqualTo(imp_privateKey.prime1));
            Assert.That(privateKey.prime2, Is.EqualTo(imp_privateKey.prime2));
            Assert.That(imp_privateKey.Verify());

            Assert.That(publicKey.modulus, Is.EqualTo(imp_publicKey.modulus));
            Assert.That(publicKey.publicExponent, Is.EqualTo(imp_publicKey.publicExponent));
        }

        [Test]
        [Retry(20)]
        public void EncryptDecrypt()
        {
            RSAPrivateKey prv = new RSAPrivateKey(512);
            _engine = new RSAEngine(prv);

            byte[] data = new byte[20];
            _rng.GetBytes(data, 0, data.Length);

            byte[] cipher = _engine.Encrypt(data, null, RSAEncryptionScheme.OAEP);
            byte[] decipher = _engine.Decrypt(cipher, null, RSAEncryptionScheme.OAEP);

            string dataHex = Convert.ToHexString(data);
            string decpHex = Convert.ToHexString(decipher);

            Assert.That(decpHex, Is.EqualTo(dataHex));
        }
    }
}
