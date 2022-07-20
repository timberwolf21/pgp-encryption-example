using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace PgpEncryption;

public static class PgpHelper
{
    #region Encrypt

    /*
     * Encrypt the file.
     */

    public static void EncryptFile(string inputFile, string outputFile, string publicKeyFile, bool armor,
        bool withIntegrityCheck)
    {
        using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
        {
            var encKey = ReadPublicKey(publicKeyStream);

            using (var bOut = new MemoryStream())
            {
                var comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(inputFile));

                comData.Close();
                var cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck,
                    new SecureRandom());

                cPk.AddMethod(encKey);
                var bytes = bOut.ToArray();

                using (Stream outputStream = File.Create(outputFile))
                {
                    if (armor)
                        using (var armoredStream = new ArmoredOutputStream(outputStream))
                        {
                            using (var cOut = cPk.Open(armoredStream, bytes.Length))
                            {
                                cOut.Write(bytes, 0, bytes.Length);
                            }
                        }
                    else
                        using (var cOut = cPk.Open(outputStream, bytes.Length))
                        {
                            cOut.Write(bytes, 0, bytes.Length);
                        }
                }
            }
        }
    }

    #endregion Encrypt

    #region Decrypt

    /*
   * decrypt a given stream.
   */

    public static void Decrypt(string inputfile, string privateKeyFile, string passPhrase, string outputFile)
    {
        if (!File.Exists(inputfile))
            throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", inputfile));

        if (!File.Exists(privateKeyFile))
            throw new FileNotFoundException(string.Format("Private Key File [{0}] not found.", privateKeyFile));

        if (string.IsNullOrEmpty(outputFile))
            throw new ArgumentNullException("Invalid Output file path.");

        using (Stream inputStream = File.OpenRead(inputfile))
        {
            using (Stream keyIn = File.OpenRead(privateKeyFile))
            {
                Decrypt(inputStream, keyIn, passPhrase, outputFile);
            }
        }
    }

    /*
    * decrypt a given stream.
    */

    public static void Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
    {
        PgpObjectFactory pgpF = null;
        PgpEncryptedDataList enc = null;
        PgpObject o = null;
        PgpPrivateKey sKey = null;
        PgpPublicKeyEncryptedData pbe = null;
        PgpSecretKeyRingBundle pgpSec = null;

        pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        // find secret key
        pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

        if (pgpF != null)
            o = pgpF.NextPgpObject();

        // the first object might be a PGP marker packet.
        if (o is PgpEncryptedDataList)
            enc = (PgpEncryptedDataList)o;
        else
            enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

        // decrypt
        foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
        {
            sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

            if (sKey != null)
            {
                pbe = pked;
                break;
            }
        }

        if (sKey == null)
            throw new ArgumentException("Secret key for message not found.");

        PgpObjectFactory plainFact = null;

        using (var clear = pbe.GetDataStream(sKey))
        {
            plainFact = new PgpObjectFactory(clear);
        }

        var message = plainFact.NextPgpObject();

        if (message is PgpCompressedData)
        {
            var cData = (PgpCompressedData)message;
            PgpObjectFactory of = null;

            using (var compDataIn = cData.GetDataStream())
            {
                of = new PgpObjectFactory(compDataIn);
            }

            message = of.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = of.NextPgpObject();
                PgpLiteralData Ld = null;
                Ld = (PgpLiteralData)message;
                using (Stream output = File.Create(outputFile))
                {
                    var unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, output);
                }
            }
            else
            {
                PgpLiteralData Ld = null;
                Ld = (PgpLiteralData)message;
                using (Stream output = File.Create(outputFile))
                {
                    var unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, output);
                }
            }
        }
        else if (message is PgpLiteralData)
        {
            var ld = (PgpLiteralData)message;
            var outFileName = ld.FileName;

            using (Stream fOut = File.Create(outputFile))
            {
                var unc = ld.GetInputStream();
                Streams.PipeAll(unc, fOut);
            }
        }
        else if (message is PgpOnePassSignatureList)
        {
            throw new PgpException("Encrypted message contains a signed message - not literal data.");
        }
        else
        {
            throw new PgpException("Message is not a simple encrypted file - type unknown.");
        }
    }

    #endregion Decrypt

    #region Private helpers

    /*
    * A simple routine that opens a key ring file and loads the first available key suitable for encryption.
    */

    private static PgpPublicKey ReadPublicKey(Stream inputStream)
    {
        inputStream = PgpUtilities.GetDecoderStream(inputStream);

        var pgpPub = new PgpPublicKeyRingBundle(inputStream);

        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        // iterate through the key rings.
        foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
        foreach (PgpPublicKey k in kRing.GetPublicKeys())
            if (k.IsEncryptionKey)
                return k;

        throw new ArgumentException("Can't find encryption key in key ring.");
    }

    /*
    * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
    */

    private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
    {
        var pgpSecKey = pgpSec.GetSecretKey(keyId);

        if (pgpSecKey == null)
            return null;

        return pgpSecKey.ExtractPrivateKey(pass);
    }

    #endregion Private helpers
}