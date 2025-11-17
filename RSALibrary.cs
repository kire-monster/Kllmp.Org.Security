using System.Security.Cryptography;

namespace Kllmp.Org.Security;

public class RSALibrary
{
    #region OaepSHA256Padding
    public static string EncriptOaepSHA256Padding(string text, string pem)
    {
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(ToPemPlain(pem, "PUBLIC")), out _);
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
            byte[] cifrado = rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(cifrado);
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
            throw new CryptographicException("Ocurrió un error durante el cifrado de RSA.", ex);
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


    public static string DecriptOaepSHA256Padding(string textEncript, string pem)
    {
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(ToPemPlain(pem, "PRIVATE")), out _);
            byte[] bytes = Convert.FromBase64String(textEncript);
            byte[] decripts = rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
            return System.Text.Encoding.UTF8.GetString(decripts);
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
            throw new CryptographicException("Ocurrió un error durante el cifrado de RSA.", ex);
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


    #region WithoutOAEPPadding
    public static string EncriptWithoutOAEPPadding(string text, string xml)
    {
        try
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.FromXmlString(xml);
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
            byte[] cifrado = rsa.Encrypt(bytes, false);
            return Convert.ToBase64String(cifrado);
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
            throw new CryptographicException("Ocurrió un error durante el cifrado de RSA.", ex);
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


    
    public static string DecriptWithoutOAEPPadding(string text, string xml)
    {
        try
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.FromXmlString(xml);
            byte[] bytes = Convert.FromBase64String(text);
            byte[] descipher = rsa.Decrypt(bytes, false);
            return Convert.ToBase64String(descipher);
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
            throw new CryptographicException("Ocurrió un error durante el cifrado de RSA.", ex);
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


    static string ToPemPlain(string pem, string key)
        => pem
        .Replace($"-----BEGIN {key} KEY-----", "")
        .Replace($"-----END {key} KEY-----", "")
        .Replace("\r", "")
        .Replace("\n", "");
}
