import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class VerifierTest {

    private static List<String> UserList;

    public static void main(String[] args) {
        try {
            Verifier.verifyCertificate("Keys/user01-x509.crt");
            Verifier.verifyPrivateKey(
                    Files.readAllBytes(Path.of("Keys/user01-pkcs8-des.key")), "user01");
            Verifier.ListFiles();
            Verifier.OpenFile("XXYYZZ11", "Files/");

            SQLite db = new SQLite("dbtest.db");
            db.createTables();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
