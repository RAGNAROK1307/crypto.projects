using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace crypto.projects
{
    public class Signing
    {
        private int FileNumber = 1; // Contador para nombrar los archivos comprimidos

        public void SignCompress(KeyPair selectedPair) // Método para firmar y comprimir
        {
            try
            {
                if (selectedPair == null) // Verifica si no se ha seleccionado ningún par de claves
                {
                    throw new Exception("No se ha seleccionado ningún par de claves.");
                }

                Console.Write("Ingrese el mensaje que desea firmar: ");
                string mensaje = Console.ReadLine(); // Solicita al usuario ingresar el mensaje

                // Crea una instancia de RSACryptoServiceProvider para firmar el mensaje
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    RSAParameters rsaParams = new RSAParameters();

                    // Obtiene los parámetros del par de claves seleccionado
                    RSAParametersJson rsaParamsJson = selectedPair.Parameters;

                    // Asigna los parámetros de la clave seleccionada al objeto RSAParameters
                    rsaParams.D = rsaParamsJson.D;
                    rsaParams.DP = rsaParamsJson.DP;
                    rsaParams.DQ = rsaParamsJson.DQ;
                    rsaParams.Exponent = rsaParamsJson.Exponent;
                    rsaParams.InverseQ = rsaParamsJson.InverseQ;
                    rsaParams.Modulus = rsaParamsJson.Modulus;
                    rsaParams.P = rsaParamsJson.P;
                    rsaParams.Q = rsaParamsJson.Q;

                    // Importa las claves seleccionadas al proveedor RSA
                    rsa.ImportParameters(rsaParams);

                    // Convierte el mensaje a bytes
                    byte[] mensajeBytes = Encoding.UTF8.GetBytes(mensaje);

                    // Guarda el mensaje en un archivo .txt
                    File.WriteAllBytes("Mensaje.txt", mensajeBytes);

                    // Guarda la clave pública en un archivo .txt
                    string publicKeyXml = rsa.ToXmlString(false);
                    File.WriteAllText("PublicKey.txt", publicKeyXml);

                    // Firma el mensaje utilizando RSA
                    byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    // Guarda la firma en un archivo .txt
                    File.WriteAllBytes("Firma.txt", firma);

                    Console.WriteLine("Firma del mensaje realizada y guardada correctamente.");

                    // Verifica si el archivo comprimido ya existe y le asigna un nombre único
                    string nombreArchivoZip = $"ArchivosComprimidos{FileNumber}.zip";
                    while (File.Exists(nombreArchivoZip))
                    {
                        FileNumber++;
                        nombreArchivoZip = $"ArchivosComprimidos{FileNumber}.zip";
                    }

                    // Crea un archivo ZIP y agrega los archivos .txt
                    using (ZipArchive zip = ZipFile.Open(nombreArchivoZip, ZipArchiveMode.Create))
                    {
                        zip.CreateEntryFromFile("Mensaje.txt", "Mensaje.txt");
                        zip.CreateEntryFromFile("PublicKey.txt", "PublicKey.txt");
                        zip.CreateEntryFromFile("Firma.txt", "Firma.txt");
                    }

                    Console.WriteLine($"Archivos comprimidos correctamente como {nombreArchivoZip}.");

                    // Elimina los archivos .txt originales después de comprimirlos
                    File.Delete("Mensaje.txt");
                    File.Delete("PublicKey.txt");
                    File.Delete("Firma.txt");
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error de criptografía: {e.Message}"); // Captura errores relacionados con criptografía
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inesperado: {ex.Message}"); // Captura otros errores inesperados
            }
        }
    }
}
