# Kllmp.Org.Security

Este proyecto incluye dos clases principales para el manejo de cifrado y descifrado de datos utilizando algoritmos simétricos (AES) y asimétricos (RSA) en .NET

## Clases

### AESLibrary

Clase estática que proporciona métodos para cifrado y descifrado utilizando AES en dos modos:

- **AES-GCM**  
  - `EncryptAESGCM(string valor, string accesoSimetrico, string codigoAutenticacionHash)`  
    Cifra datos usando AES en modo GCM, con autenticación adicional.
  - `DecryptAESGCM(string valorCifrado, string accesoSimetrico, string codigoAutenticacionHash)`  
    Descifra datos cifrados en modo GCM, validando la autenticación.

- **AES-CBC + HMAC**  
  - `EncryptAES_CBC(string plainText, string accesoSimetrico, string codigoAutenticacionHash)`  
    Cifra datos usando AES en modo CBC y añade autenticación HMAC-SHA256.
  - `DecryptAES_CBC(string valorBase64, string accesoSimetrico, string codigoAutenticacionHash)`  
    Descifra datos cifrados en modo CBC, validando la autenticación HMAC.

**Características:**
- Uso de claves y vectores de inicialización generados aleatoriamente.
- Validación de integridad mediante HMAC (CBC) y autenticación adicional (GCM).
- Manejo robusto de excepciones.

---

### RSALibrary

Clase que proporciona métodos para cifrado y descifrado de datos utilizando RSA, soportando diferentes formatos y modos de padding:

- **RSA OAEP SHA256 (PEM):**
  - `EncriptOaepSHA256Padding(string text, string pem)`  
    Cifra datos usando la clave pública en formato PEM y padding OAEP SHA256.
  - `DecriptOaepSHA256Padding(string cipher, string pem)`  
    Descifra datos usando la clave privada en formato PEM y padding OAEP SHA256.

- **RSA sin OAEP (XML):**
  - `EncriptWithoutOAEPPadding(string text, string xml)`  
    Cifra datos usando la clave pública en formato XML y padding PKCS#1 v1.5.
  - `DecriptWithoutOAEPPadding(string text, string xml)`  
    Descifra datos usando la clave privada en formato XML y padding PKCS#1 v1.5.

**Características:**
- Soporte para claves en formato PEM y XML.
- Padding OAEP con SHA256 y sin OAEP (PKCS#1 v1.5).
- Manejo robusto de excepciones.

---

## Requisitos

- .NET 8 o Superior
- C# 12

## Uso

Importar el namespace `Kllmp.Org.Security` y utilizar los métodos estáticos de las clases según el tipo de cifrado requerido.

