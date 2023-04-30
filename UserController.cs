using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

internal class UserController
{
    private List<string> DataList = new List<string>();

    private List<(int, string)> AcessList = new List<(int, string)>();

    private List<Person> UserList = new List<Person>();

    private string UserId = new string("");

    private bool LoggedIn { get; set; } = false;

    public void Login(string name, string pass)
    {
        int value = 0;
        foreach (char c in name)
        {
            value += (int)c;
        }

        Console.WriteLine($"Welcome {name}");
        Console.WriteLine($"Your Id is {value}");
        LoggedIn = true;
    }

   

    public UserController()
    {
        AcessList.Add((0, "Starting"));
    }

    public void RequireLogin()
    {
        if (!LoggedIn)
        {
            throw new Exception("User is not logged in");
        }

        
    }

    public bool AddData(string Data)
    {
        RequireLogin();

        AcessList.Add((AcessList[AcessList.Count - 1].Item1 + 1, $"User {UserId} Add To DataList " + DateTime.UtcNow));
        DataList.Add(Data);
        return true;
    }

    public Array ListData()
    {
        RequireLogin();

        AcessList.Add((AcessList[AcessList.Count - 1].Item1 + 1, $"User {UserId} Access DataList " + DateTime.UtcNow));
        return DataList.ToArray();
    }

    public Array ListAcess()
    {
        RequireLogin();

        AcessList.Add((AcessList[AcessList.Count - 1].Item1 + 1, $"User {UserId} Access ListAcess " + DateTime.UtcNow));
        return AcessList.ToArray();
    }


    public Person Register(string name, string pass,string Comments = "")
    {

        RequireLogin();

        CertificationAuthority ca = new CertificationAuthority(1);
        Person person = new Person(name, pass, ca.SignCertificate());
        UserList.Add(person);

        AcessList.Add((AcessList[AcessList.Count - 1].Item1 + 1, $"User {UserId} Added User {person} {name}" + DateTime.UtcNow));

        return person;
    }
}
internal class CertificationAuthority
{
    private RSACryptoServiceProvider privateKey;
    private RSACryptoServiceProvider publicKey;
    private int currentLevel;

    public CertificationAuthority(int startingLevel)
    {
        
        this.privateKey = new RSACryptoServiceProvider();
        this.publicKey = new RSACryptoServiceProvider();
        publicKey.ImportParameters(privateKey.ExportParameters(true));
        this.currentLevel = startingLevel;
    }

    public byte[] SignCertificate()
    {
        int level = GetCurrentLevel();
        // Create the certificate with the level and signature
        byte[] levelBytes = BitConverter.GetBytes(level);
        byte[] encryptedLevel = this.privateKey.Encrypt(levelBytes, false);

        byte[] certificateWithoutSignature = new byte[encryptedLevel.Length];
        Array.Copy(encryptedLevel, 0, certificateWithoutSignature, 0, encryptedLevel.Length);

        byte[] signature = this.privateKey.SignData(certificateWithoutSignature, new SHA256CryptoServiceProvider());

        byte[] certificate = new byte[encryptedLevel.Length + signature.Length];
        Array.Copy(encryptedLevel, 0, certificate, 0, encryptedLevel.Length);
        Array.Copy(signature, 0, certificate, encryptedLevel.Length, signature.Length);


        return certificate;
    }

    public RSACryptoServiceProvider GetPublicKey()
    {
        return this.publicKey;
    }

    public int GetCurrentLevel()
    {
        return this.currentLevel;
    }

    public void IncrementLevel()
    {
        this.currentLevel++;
    }
}
public class Person
{
    private string login;
    private string password;

    private Dictionary<int, byte[]> certificate = new Dictionary<int, byte[]>();

    public Person(string login, string password, byte[] certificate)
    {
        this.login = login;
        this.password = password;
        this.certificate.Add(0, certificate);
    }

    public bool Authenticate(string login, string password)
    {
        return this.login == login && this.password == password;
    }

    public byte[] GetCertificate(int level = 0)
    {
        return this.certificate[level];
    }
    

    public bool VerifyCertificate(RSACryptoServiceProvider caPublicKey)
    {
        // Verify the signature on the certificate using the CA's public key
        byte[] signature = new byte[128];
        Array.Copy(this.certificate[0], this.certificate[0].Length - 128, signature, 0, 128);

        byte[] certificateWithoutSignature = new byte[this.certificate[0].Length - 128];
        Array.Copy(this.certificate[0], 0, certificateWithoutSignature, 0, certificateWithoutSignature.Length);

        return caPublicKey.VerifyData(certificateWithoutSignature, new SHA256CryptoServiceProvider(), signature);
    }

    public int GetCertificateLevel(RSACryptoServiceProvider caPublicKey)
    {
        // Read the level from the certificate without disclosing the level itself
        byte[] certificateWithoutSignature = new byte[this.certificate[0].Length - 128];
        Array.Copy(this.certificate[0], 0, certificateWithoutSignature, 0, certificateWithoutSignature.Length);

        byte[] levelBytes = caPublicKey.Decrypt(certificateWithoutSignature, false);
        int level = BitConverter.ToInt32(levelBytes, 0);
        return level;
    }

    public void SetData(int level, string data)
    {

        /*RSACryptoServiceProvider publicKey = new RSACryptoServiceProvider();
        publicKey.ImportSubjectPublicKeyInfo(certificate[0], out _);

        if (level > GetCertificateLevel(publicKey))
        {
            throw new ArgumentException("Cannot set data at a higher level than the certificate level.");
        }

        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
        byte[] encryptedData = EncryptData(dataBytes, publicKey, level);
        */
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

        // Generate a new certificate
        byte[] levelBytes = BitConverter.GetBytes(1);
        byte[] encryptedLevel = rsa.Encrypt(levelBytes, false);

        byte[] certificateWithoutSignature = new byte[encryptedLevel.Length];
        Array.Copy(encryptedLevel, 0, certificateWithoutSignature, 0, encryptedLevel.Length);

        byte[] signature = rsa.SignData(certificateWithoutSignature, new SHA256CryptoServiceProvider());

        byte[] certificateNEW = new byte[encryptedLevel.Length + signature.Length];
        Array.Copy(encryptedLevel, 0, certificateNEW, 0, encryptedLevel.Length);
        Array.Copy(signature, 0, certificateNEW, encryptedLevel.Length, signature.Length);

        // Set the new certificate on the Person object
        certificate[0] = certificateNEW;

        rsa.ImportCspBlob(certificateNEW);

        // Encrypt some data using the RSA public key from the certificate
        byte[] plaintext = Encoding.UTF8.GetBytes(data);
        byte[] ciphertext = rsa.Encrypt(plaintext, false);
        UserController user = new UserController();
        user.AddData(ciphertext.ToString());
    }
    

    public string GetData(int level, RSACryptoServiceProvider privateKey)
    {
        if (!this.certificate.ContainsKey(level))
        {
            throw new ArgumentException("No data found at the given level.");
        }

        byte[] encryptedData = this.certificate[level];
        byte[] decryptedData = DecryptData(encryptedData, privateKey, level);

        return Encoding.UTF8.GetString(decryptedData);
    }

    private byte[] EncryptData(byte[] data, RSACryptoServiceProvider publicKey, int level)
    {
        byte[] levelBytes = BitConverter.GetBytes(level);

        byte[] encryptedLevelBytes = publicKey.Encrypt(levelBytes, false);

        byte[] concatenatedData = new byte[encryptedLevelBytes.Length + data.Length];
        Array.Copy(encryptedLevelBytes, concatenatedData, encryptedLevelBytes.Length);
        Array.Copy(data, 0, concatenatedData, encryptedLevelBytes.Length, data.Length);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = publicKey.ExportParameters(false).Modulus;
            aesAlg.IV = publicKey.ExportParameters(false).Exponent;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            byte[] encryptedData;
            using (System.IO.MemoryStream msEncrypt = new System.IO.MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(concatenatedData, 0, concatenatedData.Length);
                }
                encryptedData = msEncrypt.ToArray();
            }

            return encryptedData;
        }
    }

    private byte[] DecryptData(byte[] encryptedData, RSACryptoServiceProvider privateKey, int level)
    {
        byte[] decryptedData;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = privateKey.ExportParameters(true).D;
            aesAlg.IV = privateKey.ExportParameters(true).Exponent;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (System.IO.MemoryStream msDecrypt = new System.IO.MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(encryptedData, 0, encryptedData.Length);
                }
                byte[] concatenatedData = msDecrypt.ToArray();

                byte[] decryptedLevelBytes = privateKey.Decrypt(concatenatedData, false);
                int decryptedLevel = BitConverter.ToInt32(decryptedLevelBytes, 0);

                if (decryptedLevel != level)
                {
                    throw new CryptographicException("Level of decrypted data does not match expected level.");
                }

                decryptedData = new byte[concatenatedData.Length - decryptedLevelBytes.Length];
                Array.Copy(concatenatedData, decryptedLevelBytes.Length, decryptedData, 0, decryptedData.Length);
            }
        }

        return decryptedData;
    }
}
