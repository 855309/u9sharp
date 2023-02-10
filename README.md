# u9sharp
u9 cryptography library for C#. 
 
Currently supports only RSA_OAEP but I will implement AES algorithm and TLS protocol.

### Supports
- [X] RSA_OAEP with SHA-1 and MGF-1
- [X] RSA key generation
- [X] DER encoded key import/export
- [X] RSA Encryption/Decryption
- [X] OpenSSH style RandomArt generation
- [ ] AES Encryption/Decryption (soon)
- [ ] TLS protocol (soon)

#### [Demo Project](u9sharp.Demo/)

## Basic Usage
For encryption/decryption:
```cs
using System.Text;
using u9sharp;

...

// generate a new key with modulus length 1024
RSAPrivateKey privateKey = new RSAPrivateKey(1024);

// export DER encoded ASN.1 keys
privateKey.Export("prv.pem");
privateKey.GetPublicKey().Export("pub.pem");

// create engine for encryption/decryption
RSAEngine engine = new RSAEngine(privateKey);

// some data to encrypt
byte[] data = Encoding.UTF8.GetBytes("test");

// encrypt data with null label (new byte[0])
byte[] cipher = engine.Encrypt(data, null, RSAEncryptionScheme.OAEP);

// decrypt
byte[] output = engine.Decrypt(data, null, RSAEncryptionScheme.OAEP);

// write output (should be "test")
Console.WriteLine("Out: {0}", Encoding.UTF8.GetString(output));
```

You can use the ``Prime`` class to generate pseudo-primes. It uses the Rabin-Miller algorithm with 10 rounds by default:
```cs
using System.Numerics;
using u9sharp;

...

// generate a 512-bit pseudo-prime
BigInteger pprime = Prime.random_prime(512);

// you can change the number of rounds. for example:
Prime.round_num = 15;
```

Or you can use the MGF-1 implementation:
```cs
using System.Text;
using u9sharp;

...

// mask seed "foo" with length 5
byte[] mask = Masking.MGF1(Encoding.UTF8.GetBytes("foo"), 5, Helper.HashSHA1);

// output the result. (should be "1ac9075cd4")
Console.WriteLine("Out: {0}", Convert.ToHexString(mask).ToLower());
```

## License
This project is licensed under the [MIT License](LICENSE).
