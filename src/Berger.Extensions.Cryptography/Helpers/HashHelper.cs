using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Berger.Extensions.Cryptography
{
    public static class HashHelper
    {
        public static bool Validate(this string password, string salt, string hash) => CreateSalt(password, salt) == hash;
        public static string CreateSalt(this string password, string salt)
        {
            var bytes = KeyDerivation.Pbkdf2
            (
                password: password,
                iterationCount: 10000,
                numBytesRequested: 256 / 8,
                prf: KeyDerivationPrf.HMACSHA512,
                salt: salt.ToByteArray()
            );

            return Convert.ToBase64String(bytes);
        }
        public static string CreateHash()
        {
            byte[] random = new byte[128 / 8];

            using var generator = RandomNumberGenerator.Create();

            generator.GetBytes(random);

            return Convert.ToBase64String(random);
        }
        public static byte[] ToByteArray(this string value)
        {
            return Encoding.ASCII.GetBytes(value);
        }
    }
}