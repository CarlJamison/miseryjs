using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace DInjector
{
    class AES
    {
        byte[] key;

        byte[] PerformCryptography(ICryptoTransform cryptoTransform, byte[] data)
        {
            using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
        }

        public AES(string password)
        {
            this.key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public byte[] Decrypt(byte[] data)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                var iv = data.Take(16).ToArray();
                var encrypted = data.Skip(16).Take(data.Length - 16).ToArray();

                aes.Key = this.key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    return PerformCryptography(decryptor, encrypted);
            }
        }
    }
}
