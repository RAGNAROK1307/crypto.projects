using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace crypto.projects
{
    public class KeysManagement
    {
        private List<KeyPair> keyPairs; // Lista para almacenar pares de claves RSA
        private int FileNumber = 1; // Contador para nombrar los archivos comprimidos
        private Signing signingHandler; // Instancia de la clase Signing para firmar y comprimir

        public KeysManagement()
        {
            keyPairs = new List<KeyPair>(); // Inicializa la lista de pares de claves
            LoadFromJson(); // Carga las claves desde un archivo JSON al inicio
            signingHandler = new Signing(); // Inicializa la instancia de Signing para utilizarla posteriormente
        }

        public void GeneratePairKeys()
        {
            try
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    Console.WriteLine("Generando par de claves...");
                    RSAParameters privateKey = rsa.ExportParameters(true);
                    RSAParameters publicKey = rsa.ExportParameters(false);
                    RSAParameters rsaParams = rsa.ExportParameters(true);
                    int nextIndex = keyPairs.Count; // Obtiene el próximo índice para el nuevo par de claves

                    // Agrega el nuevo par de claves a la lista de keyPairs
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
                Console.WriteLine($"Error de criptografía: {e.Message}"); // Captura errores relacionados con criptografía
            }
        }

        public void DisplayKeyPairs()
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
            string selectedId = Console.ReadLine(); // Solicita al usuario ingresar el ID del par de claves seleccionado

            KeyPair selectedPair = keyPairs.Find(pair => pair.Keyid == selectedId); // Encuentra el par de claves seleccionado
            if (selectedPair != null)
            {
                signingHandler.SignCompress(selectedPair); // Llama al método SignCompress de la instancia de Signing
            }
            else
            {
                Console.WriteLine("ID de clave no válido. No se pudo realizar ninguna operación.");
            }
        }

        private void LoadFromJson()
        {
            try
            {
                if (File.Exists("claves.json"))
                {
                    string json = File.ReadAllText("claves.json"); // Lee el archivo JSON
                    var jsonData = JsonSerializer.Deserialize<Dictionary<string, List<KeyPair>>>(json); // Deserializa el JSON a un diccionario
                    keyPairs = jsonData["claves"]; // Asigna la lista de claves del JSON a la lista de keyPairs
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al cargar las claves desde el archivo JSON: {e.Message}");
            }
        }

        public void SaveToJson()
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true // Opciones de serialización para escribir el JSON con formato legible
                };

                string json = JsonSerializer.Serialize(new { claves = keyPairs }, options); // Serializa la lista de claves a JSON
                File.WriteAllText("claves.json", json); // Escribe el JSON en el archivo "claves.json"

                Console.WriteLine("Claves guardadas en claves.json."); // Mensaje de confirmación
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al guardar las claves en el archivo JSON: {e.Message}");
            }
        }
    }
}
