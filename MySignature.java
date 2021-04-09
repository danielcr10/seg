package MySignature;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class MySignature {

    private final String sigStandard;
    private PrivateKey signKey;
    private PublicKey verifyKey;
    private byte[] plainText = new byte[0];

    public MySignature(String standard) {
        this.sigStandard = standard;
    }

    public void initSign(PrivateKey privateKey) {
        this.signKey = privateKey;
    }

    public void update(byte[] plainText) throws IOException, NoSuchAlgorithmException {
//        ByteArrayOutputStream output = new ByteArrayOutputStream();
//        output.write(this.plainText);
//        output.write(plainText);
//        this.plainText = output.toByteArray();
        this.plainText = plainText;
    }

    public byte[] sign() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        // define o objeto de cifra RSA
        Cipher cipher = Cipher.getInstance(this.sigStandard.split("with")[1]);

        // encripta o digest utilizando a chave privada
        System.out.println("\nStart encryption");
        cipher.init(Cipher.ENCRYPT_MODE, signKey);

        return cipher.doFinal(getDigest(plainText));
    }

    public void initVerify(PublicKey verifyKey) {
        this.verifyKey = verifyKey;
    }

    public boolean verify(byte[] signature) throws SignatureException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // define o objeto de cifra RSA e imprime o provider utilizado
        Cipher cipher = Cipher.getInstance(this.sigStandard.split("with")[1]);

        // decripta a signature utilizando a chave publica
        cipher.init(Cipher.DECRYPT_MODE, verifyKey);
        byte[] digest = cipher.doFinal(signature);

        System.out.println(bytes2Hex(digest));
        System.out.println(bytes2Hex(this.getDigest(this.plainText)));
        return Arrays.equals(digest, this.getDigest(this.plainText));
    }

    private byte[] getDigest(byte[] plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(this.sigStandard.split("with")[0]);
        messageDigest.update(plainText);
        return messageDigest.digest();
    }

    private String bytes2Hex (byte[] text) {
        // converte o digest para hexadecimal
        StringBuilder buf = new StringBuilder();
        for (byte b : text) {
            String hex = Integer.toHexString(0x0100 + (b & 0x00FF)).substring(1);
            buf.append(hex.length() < 2 ? "0" : "").append(hex);
        }
        return buf.toString();
    }
}
