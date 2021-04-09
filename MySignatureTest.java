import java.security.*;
import MySignature.MySignature;


public class MySignatureTest {
    public static void main (String[] args) throws Exception {
        // verifica args e recebe o texto plano
        if (args.length !=1) {
            System.err.println("Usage: java DigitalSignatureExample text");
            System.exit(1);
        }
        byte[] plainText = args[0].getBytes("UTF8");

        // gera o par de chaves RSA
        System.out.println( "\nStart generating RSA key" );
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair key = keyGen.generateKeyPair();
        System.out.println( "Finish generating RSA key" );

        // define um objeto signature para utilizar SHA1 e RSA
        // e assina o texto plano com a chave privada,
        MySignature sig = new MySignature("SHA1withRSA");
        sig.initSign(key.getPrivate());
        sig.update(plainText);
        byte[] signature = sig.sign();

        // converte o signature para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < signature.length; i++) {
            String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        // imprime o signature em hexadecimal
        System.out.println( buf.toString() );

        // verifica a assinatura com a chave publica
        System.out.println( "\nStart signature verification" );
        sig.initVerify(key.getPublic());
        sig.update(plainText);
        try {
            if (sig.verify(signature)) {
                System.out.println( "Signature verified" );
            } else System.out.println( "Signature failed" );
        } catch (SignatureException se) {
            System.out.println( "Signature failed" );
        }
    }
}
