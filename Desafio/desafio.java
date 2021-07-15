
// Daniel Cunha - 1512920
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Random;

public class DeltaInfo {

    public static void main(String[] args) {
        byte[] plainText = args[1].getBytes(StandardCharsets.UTF_8);
        SecureRandom random = null;
        KeyGenerator kg = null;
        Cipher cipher = null;
        boolean passou = false;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert random != null;
        random.setSeed(args[0].getBytes());
        try {
            kg = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        kg.init(56, random);
        SecretKey key = kg.generateKey();

        try {
            cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return;
        }

        do {
            byte[] iv = generateIv();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            try {
                assert cipher != null;
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                return;
            }
            byte[] text = new byte[0];
            try {
                text = cipher.doFinal(decodeHexString(args[2]));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }

            System.out.println(new String(text) + " " + new String(iv));
            if ((new String(text)).contains("Star Wars"))
                passou = true;
        } while (!passou);

    }

    private static byte[] generateIv() {
        byte[] data = new byte[8];
        char[] chars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        for (int i = 0; i < 8; i++) {
            Random randomGenerator = new Random();
            int randomInt = randomGenerator.nextInt(10);
            data[i] = (byte) chars[randomInt];
        }
        return data;
    }

    public static byte hexToByte(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data[0];
    }

    public static byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException("String hexadecimal invalida.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }
}
