using System.Text;

namespace u9sharp.Tests
{
    [TestFixture]
    public class MGFTests
    {
        List<((string, int, Func<byte[], byte[]>), string)> _MGF1Results= new List<((string, int, Func<byte[], byte[]>), string)>()
        { 
            (("foo", 3, Helper.HashSHA1), "1ac907"),
            (("foo", 5, Helper.HashSHA1), "1ac9075cd4"),
            (("bar", 5, Helper.HashSHA1), "bc0c655e01"),
            (("bar", 50, Helper.HashSHA1), "bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876"),
            (("bar", 50, Helper.HashSHA256), "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1")
        };

        [Test]
        public void Verify_MGF1()
        {
            foreach (var entry in _MGF1Results)
            {
                byte[] seed = Encoding.UTF8.GetBytes(entry.Item1.Item1);
                int len = entry.Item1.Item2;

                Func<byte[], byte[]> hash_func = entry.Item1.Item3;

                byte[] result = Masking.MGF1(seed, len, hash_func);
                string res_str = Convert.ToHexString(result).ToLower();

                Assert.That(
                    res_str,
                    Is.EqualTo(entry.Item2),
                    String.Format("str: {0}\r\n  shl. result: {1}\r\n  mgf1 result: {2}\r\n", entry.Item1.Item1, entry.Item2, res_str)
                );
            }
        }
    }
}