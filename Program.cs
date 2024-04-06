using System;
using crypto.projects; // importa el espacio de nombres donde se encuentra KeysManagement

namespace crypto.projects
{
    class Program
    {
        static void Main()
        {
            // Crear instancias de las clases
            KeysManagement keysManager = new KeysManagement(); // Instancia de KeysManagement para gestionar las claves
            Signing signingHandler = new Signing(); // Instancia de Signing para firmar mensajes
            Decompressor decompressAndVerifyHandler = new Decompressor(); // Instancia de Decompressor para descomprimir y verificar firmas

            while (true)
            {
                Console.WriteLine("\nMenú de Gestión de Claves:");
                Console.WriteLine("1. Generar par de claves RSA");
                Console.WriteLine("2. Generar Firma (comprime la firma, la llave pública y el mensaje)");
                Console.WriteLine("3. Descomprimir y verificar firma");
                Console.WriteLine("4. Salir");

                Console.Write("Seleccione una opción: ");
                string opcion = Console.ReadLine();

                switch (opcion)
                {
                    case "1":
                        keysManager.GeneratePairKeys(); // Genera un nuevo par de claves RSA
                        break;
                    case "2":
                        keysManager.DisplayKeyPairs(); // Muestra las claves existentes y permite firmar mensajes
                        break;
                    case "3":
                        Console.Write("Ingrese la ruta del archivo comprimido (.zip): ");
                        string rutaArchivoZip = Console.ReadLine();
                        decompressAndVerifyHandler.DecompressAndVerify(rutaArchivoZip); // Descomprime y verifica una firma
                        break;
                    case "4":
                        keysManager.SaveToJson(); // Guarda las claves en un archivo JSON y sale del programa
                        return;
                    default:
                        Console.WriteLine("Opción no válida. Intente de nuevo.");
                        break;
                }
            }
        }
    }
}
