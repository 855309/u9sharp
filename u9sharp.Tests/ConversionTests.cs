using System.Numerics;
using System.Security.Cryptography;

namespace u9sharp.Tests
{
    [TestFixture]
    public class ConversionTests
    {
        private RandomNumberGenerator _rng;

        [SetUp]
        public void Setup()
        {
            _rng = RandomNumberGenerator.Create();
        }

        [Test]
        [Retry(50)]
        public void Verify_I2OSP()
        {
            BigInteger init = Prime.random_bigint(128);
            byte[] buffer = Helper.I2OSP(init, 16);

            BigInteger ex = new BigInteger(buffer, isUnsigned: true);

            Assert.That(ex.ToString(), Is.EqualTo(init.ToString()));
        }
    }
}
