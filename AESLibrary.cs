using System.Text;
using System.Security.Cryptography;

namespace Kllmp.Org.Security;

public static class AESLibrary
{
    private static readonly int HMACKeySize = 256;
    private static readonly int GcmIvLength = 12;
    private static readonly int IV_SIZE = 16;

    #region AES_GCM
    public static string EncryptAESGCM(string valor, string accesoSimetrico, string codigoAutenticacionHash)
    {
        try
        {
            byte[] key = Convert.FromBase64String(accesoSimetrico);
            byte[] iv = new byte[GcmIvLength];
            byte[] associatedData = Encoding.UTF8.GetBytes(codigoAutenticacionHash);
            RandomNumberGenerator.Fill(iv);

            using AesGcm aesGcm = new AesGcm(key);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(valor);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            aesGcm.Encrypt(iv, plaintextBytes, ciphertext, tag, associatedData);

            byte[] result = new byte[iv.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(ciphertext, 0, result, iv.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, iv.Length + ciphertext.Length, tag.Length);

            return Convert.ToBase64String(result);
        }
        catch (FormatException ex)
        {
            throw new FormatException("La cadena cifrada no está en un formato Base64 válido.", ex);
        }
        catch (ArgumentNullException ex)
        {
            throw new ArgumentNullException(ex.ParamName, ex.Message);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Ocurrió un error durante el cifrado de AES.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("Tamaño de secuencia incorrecto.", ex);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Ocurrió un error inesperado durante el proceso de descifrado.", ex);
        }
    }

    public static string DecryptAESGCM(string valorCifrado, string accesoSimetrico, string codigoAutenticacionHash)
    {
        try
        {
            byte[] key = Convert.FromBase64String(accesoSimetrico);
            byte[] inputData = Convert.FromBase64String(valorCifrado);
            byte[] associatedData = Encoding.UTF8.GetBytes(codigoAutenticacionHash);

            byte[] iv = new byte[GcmIvLength];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[inputData.Length - iv.Length - tag.Length];

            Buffer.BlockCopy(inputData, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(inputData, iv.Length, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(inputData, iv.Length + ciphertext.Length, tag, 0, tag.Length);

            using AesGcm aesGcm = new AesGcm(key);
            byte[] plaintextBytes = new byte[ciphertext.Length];
            aesGcm.Decrypt(iv, ciphertext, tag, plaintextBytes, associatedData);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
        catch (FormatException ex)
        {
            throw new FormatException("La cadena cifrada no está en un formato Base64 válido.", ex);
        }
        catch (ArgumentNullException ex)
        {
            throw new ArgumentNullException(ex.ParamName, ex.Message);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Ocurrió un error durante el cifrado de AES.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("Tamaño de secuencia incorrecto.", ex);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Ocurrió un error inesperado durante el proceso de descifrado.", ex);
        }
    }

    #endregion


    #region AES_CBC

    public static string EncryptAES_CBC(string plainText, string accesoSimetrico, string codigoAutenticacionHash)
    {
        try
        {
            byte[] aesKey = Convert.FromBase64String(accesoSimetrico);
            byte[] hmacKey = Convert.FromBase64String(codigoAutenticacionHash);
            using (var aes = new RijndaelManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = HMACKeySize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = aesKey;
                aes.GenerateIV();

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                byte[] iv_cipherText = aes.IV.Concat(cipherText).ToArray();

                using (var hmac = new HMACSHA256(hmacKey))
                {
                    byte[] hmacBytes = hmac.ComputeHash(iv_cipherText);
                    byte[] finalBytes = iv_cipherText.Concat(hmacBytes).ToArray();
                    return Convert.ToBase64String(finalBytes);
                }
            }
        }
        catch (FormatException ex)
        {
            throw new FormatException("La cadena cifrada no está en un formato Base64 válido.", ex);
        }
        catch (ArgumentNullException ex)
        {
            throw new ArgumentNullException(ex.ParamName, ex.Message);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Ocurrió un error durante el cifrado de AES.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("Tamaño de secuencia incorrecto.", ex);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Ocurrió un error inesperado durante el proceso de descifrado.", ex);
        }
    }

    public static string DecryptAES_CBC(string valorBase64, string accesoSimetrico, string codigoAutenticacionHash)
    {
        try
        {
            byte[] aesKey = Convert.FromBase64String(accesoSimetrico);
            byte[] hmacKey = Convert.FromBase64String(codigoAutenticacionHash);
            byte[] iv_cipherText_hmac = Convert.FromBase64String(valorBase64);
            int macLength = hmacKey.Length;
            int cipherTextLength = iv_cipherText_hmac.Length - macLength;

            byte[] iv = iv_cipherText_hmac.Take(IV_SIZE).ToArray();
            byte[] cipherText = iv_cipherText_hmac.Skip(IV_SIZE).Take(cipherTextLength - IV_SIZE).ToArray();
            byte[] iv_cipherText = iv.Concat(cipherText).ToArray();
            byte[] receivedHMAC = iv_cipherText_hmac.Skip(cipherTextLength).ToArray();

            using (var hmac = new HMACSHA256(hmacKey))
            {
                byte[] calculatedHMAC = hmac.ComputeHash(iv_cipherText);
                if (!receivedHMAC.SequenceEqual(calculatedHMAC))
                    return "invalido";
            }

            using (var aes = new RijndaelManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = HMACKeySize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = aesKey;
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
        catch (FormatException ex)
        {
            throw new FormatException("La cadena cifrada no está en un formato Base64 válido.", ex);
        }
        catch (ArgumentNullException ex)
        {
            throw new ArgumentNullException(ex.ParamName, ex.Message);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Ocurrió un error durante el cifrado de AES.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("Tamaño de secuencia incorrecto.", ex);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Ocurrió un error inesperado durante el proceso de descifrado.", ex);
        }
    }

    #endregion
}
