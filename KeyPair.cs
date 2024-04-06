using System.Security.Cryptography;

namespace crypto.projects
{
    public class KeyPair
    {
        public string Keyid { get; set; } // Representa el identificador de un par de claves.
        public string PrivateKey { get; set; } // Almacena la clave privada en formato base64.
        public string PublicKey { get; set; } // Almacena la clave pública en formato base64.
        public RSAParametersJson Parameters { get; set; } // Almacena los parámetros RSA en formato JSON.
    }

    public class RSAParametersJson
    {
        public byte[] D { get; set; } // Almacena el exponente privado.
        public byte[] DP { get; set; } // Almacena el exponente privado modulado por (P-1).
        public byte[] DQ { get; set; } // Almacena el exponente privado modulado por (Q-1).
        public byte[] Exponent { get; set; } // Almacena el exponente público.
        public byte[] InverseQ { get; set; } // Almacena el inverso de Q módulo P.
        public byte[] Modulus { get; set; } // Almacena el módulo.
        public byte[] P { get; set; } // Almacena el primer factor del módulo.
        public byte[] Q { get; set; } // Almacena el segundo factor del módulo.
    }
}
