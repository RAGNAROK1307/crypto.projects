using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace crypto.projects
{
    public class Decompressor
    {
        public void DecompressAndVerify(string rutaArchivoZip)
        {
            try
            {
                if (!File.Exists(rutaArchivoZip)) // Verifica si el archivo ZIP especificado existe.
                {
                    Console.WriteLine("El archivo especificado no existe."); // Muestra un mensaje si el archivo no existe.
                    return; // Sale del método si el archivo no existe.
                }

                // Crea una ruta para extraer los archivos del ZIP.
                string extractPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ExtractedFiles");

                // Extrae los archivos del ZIP en la ruta especificada.
                ZipFile.ExtractToDirectory(rutaArchivoZip, extractPath);

                // Lee el contenido de los archivos descomprimidos: mensaje, clave pública y firma.
                string mensaje = File.ReadAllText(Path.Combine(extractPath, "Mensaje.txt"));
                string publicKeyXml = File.ReadAllText(Path.Combine(extractPath, "PublicKey.txt"));
                byte[] firma = File.ReadAllBytes(Path.Combine(extractPath, "Firma.txt"));

                // Crea una instancia de RSACryptoServiceProvider y carga la clave pública.
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKeyXml); // Carga la clave pública en el objeto RSA.

                    // Convierte el mensaje a bytes.
                    byte[] mensajeBytes = Encoding.UTF8.GetBytes(mensaje);

                    // Verifica la firma utilizando RSA.
                    bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    if (verificado)
                    {
                        Console.WriteLine("La firma es válida."); // Muestra un mensaje si la firma es válida.
                    }
                    else
                    {
                        Console.WriteLine("La firma es inválida."); // Muestra un mensaje si la firma es inválida.
                    }
                }

                // Elimina los archivos descomprimidos después de la verificación.
                Directory.Delete(extractPath, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}"); // Captura y muestra cualquier excepción que ocurra.
            }
        }
    }
}
