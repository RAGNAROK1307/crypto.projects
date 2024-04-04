using crypto.projects;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

// Declaración del espacio de nombres crypto.projects
namespace crypto.projects
{
    // Declaración de la clase Keys
    public class Keys
    {
        // Lista que almacenará los pares de claves RSA
        private List<KeyPair> keyPairs;

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
                Console.WriteLine("2. Mostrar claves existentes");
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

                    int nextIndex = keyPairs.Count;

                    // Agregar el nuevo par de claves a la lista existente
                    keyPairs.Add(new KeyPair
                    {
                        Keyid = nextIndex.ToString(),
                        PrivateKey = Convert.ToBase64String(privateKey.D),
                        PublicKey = Convert.ToBase64String(publicKey.Modulus)
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
        }

        // Método para guardar las claves en un archivo JSON
        private void SaveToJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            // Serializar la lista de pares de claves a JSON
            string json = JsonSerializer.Serialize(new { claves = keyPairs }, options);

            // Guardar el JSON en un archivo
            File.WriteAllText("claves.json", json);

            Console.WriteLine("Claves guardadas en claves.json.");
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
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al cargar las claves desde el archivo JSON: {e.Message}");
            }
        }
    }

    // Clase que representa un par de claves RSA
    public class KeyPair
    {
        public string Keyid { get; set; }
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
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