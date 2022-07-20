namespace PgpEncryption;

internal class Program
{
    private static void Main(string[] args)
    {
        if (args == null)
            Console.WriteLine("args is null"); // Check for null array
        else
            switch (args[0])
            {
                case "GenerateKey":
                {
                    var pgp = new Pgp();
                    pgp.GenerateKey("user@email.com", "P@ssw0rd", @"C:\tmp\test\pgp\test_");
                    Console.WriteLine("Keys generated!!");
                    break;
                }
                case "EncryptFile":
                {
                    PgpHelper.EncryptFile(@"C:\\tmp\test\pgp\test.txt",
                        @"C:\\tmp\test\pgp\test_encrypted.txt",
                        @"C:\tmp\test\pgp\test_pub.asc",
                        true,
                        true
                    );
                    Console.WriteLine("File Encrypted!!");
                    break;
                }
                case "DecryptFile":
                {
                    PgpHelper.Decrypt(@"C:\\tmp\test\pgp\test_encrypted.txt", @"C:\tmp\test\pgp\test_secret.asc",
                        "P@ssw0rd",
                        @"C:\\tmp\test\pgp\test_decrypted.txt");
                    Console.WriteLine("File Decrypted!!");
                    break;
                }
            }
    }
}