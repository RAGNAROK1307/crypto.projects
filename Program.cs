using crypto.projects;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

// Declaración del espacio de nombres crypto.projects
namespace crypto.projects
{
    // Declaración de la clase Keys
    public class Keys
    {
        // Lista que almacenará los pares de claves RSA
        private List<KeyPair> keyPairs;

        private int FileNumber = 1; // Variable para contar el número de archivos comprimidos existentes

        // Constructor de la clase Keys
        public Keys()
        {
            keyPairs = new List<KeyPair>();
            LoadFromJson(); // Cargar claves existentes desde el archivo JSON al inicializar
        }

        // Método que maneja el menú de opciones para la gestión de claves
        public void ManageKeysMenu()
        {
            while (true)
            {
                Console.WriteLine("\nMenú de Gestión de Claves:");
                Console.WriteLine("1. Generar par de claves RSA");
                Console.WriteLine("2. Generar Firma (comprime la firma, la llave publica y el mensaje");
                Console.WriteLine("3. Salir");

                Console.Write("Seleccione una opción: ");
                string opcion = Console.ReadLine();

                switch (opcion)
                {
                    case "1":
                        GeneratePairKeys();
                        break;
                    case "2":
                        DisplayKeyPairs();
                        break;
                    case "3":
                        SaveToJson();
                        return;
                    default:
                        Console.WriteLine("Opción no válida. Intente de nuevo.");
                        break;
                }
            }
        }

        // Método para generar un nuevo par de claves RSA
        private void GeneratePairKeys()
        {
            try
            {
                // Crear una instancia de la clase RSACryptoServiceProvider
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    Console.WriteLine("Generando par de claves...");

                    // Generar el par de claves pública y privada
                    RSAParameters privateKey = rsa.ExportParameters(true);
                    RSAParameters publicKey = rsa.ExportParameters(false);
                    RSAParameters rsaParams = rsa.ExportParameters(true);


                    int nextIndex = keyPairs.Count;

                    // Agregar el nuevo par de claves a la lista existente
                    keyPairs.Add(new KeyPair
                    {
                        Keyid = nextIndex.ToString(),
                        PrivateKey = Convert.ToBase64String(privateKey.D),
                        PublicKey = Convert.ToBase64String(publicKey.Modulus),
                        Parameters = new RSAParametersJson
                        {
                            D = rsaParams.D,
                            DP = rsaParams.DP,
                            DQ = rsaParams.DQ,
                            Exponent = rsaParams.Exponent,
                            InverseQ = rsaParams.InverseQ,
                            Modulus = rsaParams.Modulus,
                            P = rsaParams.P,
                            Q = rsaParams.Q
                        }

                    });

                    Console.WriteLine("Par de claves generado y agregado.");
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error de criptografía: {e.Message}");
            }
        }

        // Método para mostrar las claves existentes
        // En el método DisplayKeyPairs, después de seleccionar un par de claves válidas, llamar  SignCompress
        private void DisplayKeyPairs()
        {
            Console.WriteLine("\nClaves existentes:");
            foreach (var keyPair in keyPairs)
            {
                Console.WriteLine($"Keyid: {keyPair.Keyid}");
                Console.WriteLine($"Public Key: {keyPair.PublicKey}");
                Console.WriteLine($"Private Key: {keyPair.PrivateKey}");
                Console.WriteLine();
            }

            Console.Write("Ingrese el ID del par de claves que desea seleccionar: ");
            string selectedId = Console.ReadLine();

            // Buscar el par de claves con el ID seleccionado
            KeyPair selectedPair = keyPairs.Find(pair => pair.Keyid == selectedId);
            if (selectedPair != null)
            {
                 SignCompress(selectedPair); // Llamar a  SignCompress con las claves seleccionadas
            }
            else
            {
                Console.WriteLine("ID de clave no válido. No se pudo realizar ninguna operación.");
            }
        }

        private void  SignCompress(KeyPair selectedPair)
        {
            try
            {
                if (selectedPair == null)
                {
                    throw new Exception("No se ha seleccionado ningún par de claves.");
                }

                Console.Write("Ingrese el mensaje que desea firmar: ");
                string mensaje = Console.ReadLine();

                // Crear una instancia de la clase RSACryptoServiceProvider
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    RSAParameters rsaParams = new RSAParameters();


                    // Obtener los parámetros del par de claves seleccionado
                    RSAParametersJson rsaParamsJson = selectedPair.Parameters;

                    // Asignar los parámetros de la clave seleccionada al objeto RSAParameters
                    rsaParams.D = rsaParamsJson.D;
                    rsaParams.DP = rsaParamsJson.DP;
                    rsaParams.DQ = rsaParamsJson.DQ;
                    rsaParams.Exponent = rsaParamsJson.Exponent;
                    rsaParams.InverseQ = rsaParamsJson.InverseQ;
                    rsaParams.Modulus = rsaParamsJson.Modulus;
                    rsaParams.P = rsaParamsJson.P;
                    rsaParams.Q = rsaParamsJson.Q;

                    // Importar las claves seleccionadas al proveedor RSA
                    rsa.ImportParameters(rsaParams);

                    // Convertir el mensaje a bytes
                    byte[] mensajeBytes = Encoding.UTF8.GetBytes(mensaje);

                    // Guardar mesanje en un archivo .txt
                    File.WriteAllBytes("Mensaje.txt", mensajeBytes);

                    // Guardar la clave pública en un archivo .txt
                    string publicKeyXml = rsa.ToXmlString(false);
                    File.WriteAllText("PublicKey.txt", publicKeyXml);

                    // Firmar el mensaje utilizando RSA
                    byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    // Guardar la firma en un archivo .txt
                    File.WriteAllBytes("Firma.txt", firma);

                    Console.WriteLine("Firma del mensaje realizada y guardada correctamente.");

                    // Verificar si el archivo comprimido ya existe
                    string nombreArchivoZip = $"ArchivosComprimidos{FileNumber}.zip";
                    while (File.Exists(nombreArchivoZip))
                    {
                        FileNumber++;
                        nombreArchivoZip = $"ArchivosComprimidos{FileNumber}.zip";
                    }

                    // Crear un archivo ZIP y agregar los archivos .txt
                    using (ZipArchive zip = ZipFile.Open(nombreArchivoZip, ZipArchiveMode.Create))
                    {
                        zip.CreateEntryFromFile("Mensaje.txt", "Mensaje.txt");
                        zip.CreateEntryFromFile("PublicKey.txt", "PublicKey.txt");
                        zip.CreateEntryFromFile("Firma.txt", "Firma.txt");
                    }

                    Console.WriteLine($"Archivos comprimidos correctamente como {nombreArchivoZip}.");

                    // Eliminar los archivos .txt originales
                    File.Delete("Mensaje.txt");
                    File.Delete("PublicKey.txt");
                    File.Delete("Firma.txt");


                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error de criptografía: {e.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inesperado: {ex.Message}");
            }
        }


        // Método para guardar las claves en un archivo JSON
        private void SaveToJson()
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true
                };

                // Serializar la lista de pares de claves con parámetros a JSON
                string json = JsonSerializer.Serialize(new { claves = keyPairs }, options);

                // Guardar el JSON en un archivo
                File.WriteAllText("claves.json", json);

                Console.WriteLine("Claves guardadas en claves.json.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al guardar las claves en el archivo JSON: {e.Message}");
            }
        }



        // Método para cargar las claves desde un archivo JSON
        private void LoadFromJson()
        {
            try
            {
                if (File.Exists("claves.json"))
                {
                    // Leer el JSON desde el archivo
                    string json = File.ReadAllText("claves.json");

                    // Deserializar el JSON a una lista de pares de claves
                    var jsonData = JsonSerializer.Deserialize<Dictionary<string, List<KeyPair>>>(json);

                    // Actualizar la lista de claves
                    keyPairs = jsonData["claves"];

                    // Mostrar las claves cargadas para verificar
                    Console.WriteLine("\nClaves cargadas desde el archivo JSON:");
                    foreach (var keyPair in keyPairs)
                    {
                        Console.WriteLine($"Keyid: {keyPair.Keyid}");
                        Console.WriteLine($"Public Key: {keyPair.PublicKey}");
                        Console.WriteLine($"Private Key: {keyPair.PrivateKey}");
                        RSAParametersJson rsaParamsJson = keyPair.Parameters;
                        Console.WriteLine($"D: {Convert.ToBase64String(rsaParamsJson.D)}");
                        Console.WriteLine($"DP: {Convert.ToBase64String(rsaParamsJson.DP)}");
                        Console.WriteLine($"DQ: {Convert.ToBase64String(rsaParamsJson.DQ)}");
                        Console.WriteLine($"Exponent: {Convert.ToBase64String(rsaParamsJson.Exponent)}");
                        Console.WriteLine($"InverseQ: {Convert.ToBase64String(rsaParamsJson.InverseQ)}");
                        Console.WriteLine($"Modulus: {Convert.ToBase64String(rsaParamsJson.Modulus)}");
                        Console.WriteLine($"P: {Convert.ToBase64String(rsaParamsJson.P)}");
                        Console.WriteLine($"Q: {Convert.ToBase64String(rsaParamsJson.Q)}");
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al cargar las claves desde el archivo JSON: {e.Message}");
            }
        }


        // Clase que representa un par de claves RSA
        public class KeyPair
        {
            public string Keyid { get; set; }
            public string PrivateKey { get; set; }
            public string PublicKey { get; set; }
            public RSAParametersJson Parameters { get; set; }
        }

        public class RSAParametersJson
        {
            public byte[] D { get; set; }
            public byte[] DP { get; set; }
            public byte[] DQ { get; set; }
            public byte[] Exponent { get; set; }
            public byte[] InverseQ { get; set; }
            public byte[] Modulus { get; set; }
            public byte[] P { get; set; }
            public byte[] Q { get; set; }
        }
    }

    // Clase principal del programa
    class Program
    {
        static void Main()
        {
            // Crear una instancia de la clase Keys
            Keys keyManager = new Keys();

            // Ejecutar el menú de gestión de claves
            keyManager.ManageKeysMenu();
        }
    }
}







/*class Program
{
    static void Main()
    {
        try
        {
            // Crear una instancia de la clase RSACryptoServiceProvider
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Generar el par de claves pública y privada
                RSAParameters privateKey = rsa.ExportParameters(true);
                RSAParameters publicKey = rsa.ExportParameters(false);


                // Guardar la clave pública en un archivo.
                File.WriteAllText("publicKey.txt", ToXmlString(publicKey));

                // Firmar el archivo de texto
                string mensaje = "Hola, mundo!";
                byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
                byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Guardar la firma en un archivo
                File.WriteAllBytes("firma.txt", firma);

                // Verificar la firma
                bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                if (verificado)
                {
                    Console.WriteLine("La firma es válida.");
                }
                else
                {
                    Console.WriteLine("La firma es inválida.");
                }
            }



        }
        catch (CryptographicException e)
        {
            Console.WriteLine($"Error de criptografía: {e.Message}");
        }
    }

    // Tip Método para convertir los parámetros RSA a XML
    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new System.IO.StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}*/
