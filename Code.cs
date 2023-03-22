using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class AesEncryption
{
    public static void Main()
    {
        string plainText = "This is a string to encrypt.";
        string password = "Your secure password";

        // Encrypt the string and get the encrypted byte array
        byte[] encrypted = EncryptStringToBytes_Aes(plainText, password);
        // Decrypt the encrypted byte array back to the original string
        string decrypted = DecryptStringFromBytes_Aes(encrypted, password);

        Console.WriteLine("Encrypted: {0}", BitConverter.ToString(encrypted));
        Console.WriteLine("Decrypted: {0}", decrypted);
    }

    public static byte[] EncryptStringToBytes_Aes(string plainText, string password)
    {
        using (Aes aes = Aes.Create()) // Create an AES instance
        {
            // Derive the key from the given password and the AES instance's IV (Initialization Vector)
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, aes.IV);
            // Set the AES key based on the derived key
            aes.Key = key.GetBytes(aes.KeySize / 8);

            // Create a memory stream to store the encrypted data
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // Create a crypto stream to perform encryption and write it to the memory stream
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    // Write the plain text to the crypto stream, which encrypts it and writes it to the memory stream
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }

                // Get the encrypted data as a byte array
                byte[] encrypted = msEncrypt.ToArray();
                // Create a result byte array that includes both the IV and the encrypted data
                byte[] result = new byte[aes.IV.Length + encrypted.Length];

                // Copy the IV and encrypted data into the result byte array
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);

                return result;
            }
        }
    }

    public static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, string password)
    {
        using (Aes aes = Aes.Create()) // Create an AES instance
        {
            // Split the combined byte array into the IV and the encrypted data
            byte[] iv = new byte[aes.IV.Length];
            byte[] cipherText = new byte[cipherTextCombined.Length - iv.Length];

            Buffer.BlockCopy(cipherTextCombined, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(cipherTextCombined, iv.Length, cipherText, 0, cipherText.Length);

            // Derive the key from the given password and the extracted IV
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, iv);
            // Set the AES key based on the derived key
            aes.Key = key.GetBytes(aes.KeySize / 8);
            // Set the AES IV to the extracted IV
            aes.IV = iv;

            // Create a memory stream to read the encrypted data
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                // Create a crypto stream to perform decryption and read it from the memory stream
                using (CryptoStream csDecrypt = new CryptoStream(ms Decrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
{
// Read the decrypted data from the crypto stream into a string
using (StreamReader srDecrypt = new StreamReader(csDecrypt))
{
return srDecrypt.ReadToEnd();
}
}
}
}
}
}
