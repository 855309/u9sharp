using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace u9sharp
{
    public class RandomArt
    {
        // private static int w = 17, h = 9;
        private static char[] symbols = {' ', '.', 'o', '+', '=', '*', 'B', '0', 'X', '@', '%', '&', '#', '/', '^', 'S', 'E'};
        private static List<((int, int), int)> vnum = new List<((int, int), int)>();

        public static string Generate(byte[] fingerprint, string title, int w = 17, int h = 9)
        {
            char[,] art = new char[h, w];
            for (int i = 0; i < h; i++)
            {
                for (int j = 0; j < w; j++)
                {
                    vnum.Add(((i, j), 0));
                    art[i, j] = symbols[0];
                }
            }

            (int x, int y) = ((h - 1) / 2, (w - 1) / 2); // orijin

            foreach (byte b in fingerprint)
            {
                string nopad = Convert.ToString(Convert.ToInt32(b), 2);
                string pad = new string('0', 8 - nopad.Length) + nopad;

                string[] instr = Enumerable.Range(0, 4).Select(i => pad.Substring(i * 2, 2)).Reverse().ToArray();
                foreach (string ins in instr)
                {
                    // X - 0/yukarı 1/aşağı
                    // Y - 0/sol 1/sağ

                    if (ins[0] == '0' && x != 0)
                    {
                        x--;
                    }
                    else if (ins[0] == '1' && x != h - 1)
                    {
                        x++;
                    }

                    if (ins[1] == '0' && y != 0)
                    {
                        y--;
                    }
                    else if (ins[1] == '1' && y != w - 1)
                    {
                        y++;
                    }

                    for (int n = 0; n < vnum.Count(); n++)
                    {
                        ((int, int), int) p = vnum[n];
                        if (p.Item1 == (x, y))
                        {
                            vnum[n] = ((x,y), (p.Item2 + 1) % 15);
                            art[x, y] = symbols[vnum[n].Item2];
                        }
                    }
                }
            }

            art[(h - 1) / 2, (w - 1) / 2] = 'S';
            art[x, y] = 'E';

            if (title.Length > w - 2)
            {
                title = title.Substring(0, w - 4) + "..";
            }

            string oddpad;
            if (title.Length % 2 == 0)
            {
                oddpad = " ";
            }
            else
            {
                oddpad = "";
            }

            string liR = String.Concat(Enumerable.Repeat("-", (w - (oddpad + title).Length - 2) / 2));
            string fnl = "+" + liR + $"[{oddpad + title}]" + liR + "+" + "\r\n";
            for (int rw = 0; rw < h; rw++)
            {
                fnl += "|";
                fnl += String.Concat(Enumerable.Range(0, w).Select(i => art[rw, i]));
                fnl += "|";

                fnl += "\r\n";
            }
            fnl += "+" + String.Concat(Enumerable.Repeat("-", w)) + "+";

            return fnl;
        }
    }
}
