import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Verifier {

    private static byte[] salt = {
            (byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
            (byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3
    };

    private static PublicKey pubKey;
    private static PrivateKey prvKey;

    public static String encryptPswd(String pswd) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert md != null;
        return bytes2Hex(md.digest((pswd + new String(salt)).getBytes()));
    }

    public static void WriteFile(byte[] text) {
        try {
            File myObj = new File("Files/filename.docx");
            if (myObj.createNewFile())
                System.out.println("File created: " + myObj.getName());
            try (FileOutputStream stream = new FileOutputStream("Files/filename.docx")) {
                stream.write(text);
            }
            System.out.println("Successfully wrote to the file.");
        } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public static String OpenFile(String filename, String path) {
        String auxfilename;
        byte[] plainText;

        if (filename.contains("."))
            auxfilename = filename.split("\\.")[0];
        else
            auxfilename = filename;

        try {
            //Open envelope
            byte[] indexEnv = Files.readAllBytes(Path.of(path + auxfilename + ".env"));
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, prvKey);
            byte[] seed = cipher.doFinal(indexEnv);

            //Decrypt file
            byte[] indexEnc = Files.readAllBytes(Path.of(path + auxfilename + ".enc"));
            SecretKey sctKey = GetSecret(new String(seed));
            cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sctKey);
            plainText = cipher.doFinal(indexEnc);

            //Verify Signature
            verifySignature(prvKey, plainText);

            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(prvKey);
            sig.update(plainText);
            byte[] signatureCalc = sig.sign();
            byte[] signatureFile = Files.readAllBytes(Path.of(path + auxfilename + ".asd"));
            if ((new String(signatureCalc)).contentEquals(new String(signatureFile)))
                System.out.println("Signature Verified");
            else {
                System.out.println("Signature Verification failed");
                return null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        if (!filename.contentEquals("index"))
            WriteFile(plainText);
        return new String(plainText);
    }

    public static List<String> ListFiles() {
        String text = OpenFile("index", "Files/");
        assert text != null;
        String[] aux = (text).split("\n");
        return new ArrayList<>(Arrays.asList(aux));
    }

    public static boolean verifyPrivateKey(byte[] key, String secretPhrase) {
        try {
            System.out.println("Verifying private key...");
            byte[] b = new byte[2048];
            new Random().nextBytes(b);
            byte[] decrypted = decryptPrivateKey(key, secretPhrase, "DES/ECB/PKCS5Padding");
            assert decrypted != null;
            String aux = new String(decrypted).replace("-----BEGIN PRIVATE KEY-----\n", "")
                    .replace("-----END PRIVATE KEY-----\n", "");
            PrivateKey pkey = GetPrivate(Base64.getMimeDecoder().decode(aux));
            return verifySignature(pkey, b);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean verifySignature(PrivateKey pkey, byte[] message) {
        try {
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(pkey);
            sig.update(message);
            byte[] signature = sig.sign();

            sig.initVerify(pubKey); //get pubkey from user
            sig.update(message);
            if (sig.verify(signature)) {
                System.out.println("Key verified");
                prvKey = pkey;
                return true;
            }
        } catch (Exception e) {
            System.out.println("Key verification failed");
            e.printStackTrace();
            return false;
        }
        return false;
    }

    public static byte[] decryptPrivateKey(byte[] key, String SecretPhrase, String Alg) {
        try {
            System.out.println("  Decrypting private key...");
            SecretKey skey = GetSecret(SecretPhrase);
            Cipher cipher = Cipher.getInstance(Alg);
            cipher.init(Cipher.DECRYPT_MODE, skey);
            return cipher.doFinal(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey GetPrivate(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec ks = new PKCS8EncodedKeySpec(key);
        PrivateKey pkey = KeyFactory.getInstance("RSA").generatePrivate(ks);
        System.out.println("  Decrypted private key: " + bytes2Hex(pkey.getEncoded()));
        return pkey;
    }

    public static SecretKey GetSecret(String SecretPhrase) {
        KeyGenerator keyGen;
        try {
            System.out.println("\tRecreating symmetric key...");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(SecretPhrase.getBytes());
            keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56, random);
            SecretKey key = keyGen.generateKey();
            System.out.println("\tSymmetric key restored: " + bytes2Hex(key.getEncoded()));
            return key;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifyCertificate(String path) {
        CertificateFactory cf;
        X509Certificate certificate;
        System.out.println("Verifying Certificate...");
        //Create X509 instance
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
            return false;
        }
        try {
            certificate = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream((new FileInputStream(Path.of(path).toAbsolutePath().toString()))
                            .readAllBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        //Verify Validity
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
            return false;
        }
        pubKey = certificate.getPublicKey();
        System.out.println("Certificate is valid");
        return true;

        /*//Cert Path Verification
        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance("JKS");
            InputStream keyStoreStream = Verifier.class.getResourceAsStream("kst4.jks");
            trustStore.load(keyStoreStream, "otimasenha".toCharArray());

            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(certificate);

            CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
            CertPathBuilderResult certPathBuilderResult = certPathBuilder.build(certPathParameters);
            CertPath certPath = certPathBuilderResult.getCertPath();

            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            PKIXParameters validationParameters = new PKIXParameters(trustStore);
            validationParameters.setRevocationEnabled(true);
            X509CertSelector keyUsageSelector = new X509CertSelector();
            //signature checking
            keyUsageSelector.setKeyUsage(new boolean[]{true, false, true});
            validationParameters.setTargetCertConstraints(keyUsageSelector);
            PKIXCertPathValidatorResult result =
                    (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, validationParameters);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;*/
    }

    public static String bytes2Hex(byte[] text) {
        // converte o digest para hexadecimal
        StringBuilder buf = new StringBuilder();
        for (byte b : text) {
            String hex = Integer.toHexString(0x0100 + (b & 0x00FF)).substring(1);
            buf.append(hex.length() < 2 ? "0" : "").append(hex);
        }
        return buf.toString();
    }
}
