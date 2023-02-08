using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp
{
    public class Masking
    {
        public static byte[] MGF1(byte[] seed, int l, Func<byte[], byte[]> hash_func)
        {
            // https://en.wikipedia.org/wiki/Mask_generation_function
            List<byte> T = new List<byte>();

            int i = 0;
            while (T.Count() < l)
            {
                byte[] c = Helper.I2OSP(i, 4);
                Array.Reverse(c);

                List<byte> app = new List<byte>(seed);
                app.AddRange(c);

                byte[] ax = hash_func(app.ToArray());
                T.AddRange(ax);
                
                i++;
            }

            return T.GetRange(0, l).ToArray();
        }
    }
}
