using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace PgpEncryption;

public class Pgp
{
    public void GenerateKey(string username, string password, string keyStoreUrl)
    {
        IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
        kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
        var kp = kpg.GenerateKeyPair();

        var out1 = new FileInfo(string.Format("{0}secret.asc", keyStoreUrl)).OpenWrite();
        var out2 = new FileInfo(string.Format("{0}pub.asc", keyStoreUrl)).OpenWrite();

        ExportKeyPair(out1, out2, kp.Public, kp.Private, username, password.ToCharArray(), true);
    }

    private static void ExportKeyPair(
        Stream secretOut,
        Stream publicOut,
        AsymmetricKeyParameter publicKey,
        AsymmetricKeyParameter privateKey,
        string identity,
        char[] passPhrase,
        bool armor)
    {
        if (armor) secretOut = new ArmoredOutputStream(secretOut);

        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification,
            PublicKeyAlgorithmTag.RsaGeneral,
            publicKey,
            privateKey,
            DateTime.Now,
            identity,
            SymmetricKeyAlgorithmTag.Cast5,
            passPhrase,
            null,
            null,
            new SecureRandom()
        );

        secretKey.Encode(secretOut);

        secretOut.Close();

        if (armor) publicOut = new ArmoredOutputStream(publicOut);

        var key = secretKey.PublicKey;

        key.Encode(publicOut);

        publicOut.Close();
    }
}