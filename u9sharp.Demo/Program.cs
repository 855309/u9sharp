using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using u9sharp;
using u9sharp.RSA;

namespace u9sharp.Demo
{
    class Program
    {
        static bool yesno(string msg)
        {
            string info;
            do
            {
                Console.Write("{0} [Y/n]: ", msg);
                info = Console.ReadLine() ?? string.Empty;
                info = info.ToLower();
            }
            while (info != "y" && info != "n" && info != string.Empty);

            return (info == "y" || info == string.Empty);
        }

        static void Main(string[] args)
        {
            RSAEngine _engine = new RSAEngine();

            if (yesno("Generate new private key?"))
            {
                Console.WriteLine("Generating a 1024-bit RSA private key...");
                RSAPrivateKey privateKey = new RSAPrivateKey(1024);
                _engine = new RSAEngine(privateKey);
                Console.WriteLine();

                Console.WriteLine("Fingerprint random art of generated private key:");
                Console.WriteLine(privateKey.GetRandomArt());
                Console.WriteLine();

                if (yesno("Do you want to save the private key?"))
                {
                    privateKey.Export("key.pem");
                    Console.WriteLine("Key exported to 'key.pem'.");
                }

                Console.WriteLine();

                if (yesno("Do you want to save the public key?"))
                {
                    privateKey.GetPublicKey().Export("pub.pem");
                    Console.WriteLine("Key exported to 'pub.pem'.");
                }
            }
            else
            {
                if (yesno("Import private key? (Write 'n' for public key.)"))
                {
                    Console.Write("Enter private key path: ");
                    string path = Console.ReadLine() ?? string.Empty;
                    if (path == string.Empty)
                    {
                        Environment.Exit(-1);
                    }
                    else
                    {
                        _engine = new RSAEngine(new RSAPrivateKey(path));
                    }
                }
                else
                {
                    Console.Write("Enter public key path: ");
                    string path = Console.ReadLine() ?? string.Empty;
                    if (path == string.Empty)
                    {
                        Environment.Exit(-1);
                    }
                    else
                    {
                        _engine = new RSAEngine(new RSAPublicKey(path));
                    }
                }
            }

            Console.WriteLine();

            while (true)
            {
                Console.Write("> ");
                string input = Console.ReadLine() ?? string.Empty;
                if (input != string.Empty)
                {
                    if (input == "encrypt")
                    {
                        Console.Write("Input to be encrypted: ");
                        string msg = Console.ReadLine() ?? string.Empty;
                        byte[] data = Encoding.UTF8.GetBytes(msg);

                        Console.Write("Label: ");
                        string label = Console.ReadLine() ?? string.Empty;

                        byte[] cipher = _engine.Encrypt(data, label, RSAEncryptionScheme.OAEP);
                        Console.WriteLine("Encrypted: {0}", Convert.ToBase64String(cipher));
                    }
                    else if (input == "decrypt")
                    {
                        Console.Write("Input to be decrypted (base64): ");
                        string msg = Console.ReadLine() ?? string.Empty;
                        byte[] data = Convert.FromBase64String(msg);

                        Console.Write("Label: ");
                        string label = Console.ReadLine() ?? string.Empty;

                        byte[] cipher = _engine.Decrypt(data, label, RSAEncryptionScheme.OAEP);
                        Console.WriteLine("Output: {0}", Encoding.UTF8.GetString(cipher));
                    }
                    else if (input == "exit")
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("Wrong command. Type 'exit' to exit.");
                    }

                    Console.WriteLine();
                }
            }
        }
    }
}