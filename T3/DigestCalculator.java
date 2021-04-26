import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.MatchResult;
import java.util.stream.Stream;

public class DigestCalculator {

    private final String digestType;
    private final String filePath;
    private final String folderPath;
    private final HashMap<String, byte[]> FileDic = new HashMap<>();

    //Constructor
    public DigestCalculator(String digType, String filePth, String folderPth) {
        digestType = digType;
        filePath = filePth;
        folderPath = folderPth;
    }

    //Add files to hashmap
    private void addFiles(Path path) {
        String file = path.toAbsolutePath().toString();
        byte[] digest = new byte[0];
        try {
            digest = Calculate(file);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("Adding " + file + " to HashMap - " + digestType + ": " + bytes2Hex(digest));
        FileDic.put(file, digest);
    }

    //Calculate file digest
//    TODO: Trocar para private
    private byte[] Calculate(String file) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(digestType);
        try (InputStream is = Files.newInputStream(Paths.get(file).toAbsolutePath());
             DigestInputStream dis = new DigestInputStream(is, md))
        {
            while (dis.read() != -1);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return md.digest();
    }

    //Checks everything
    public void VerifyDigests() {
        //get all files in folder
        try (Stream<Path> paths = Files.walk(Paths.get(folderPath))) {
            paths
                    .filter(Files::isRegularFile)
                    .forEach(this::addFiles);

        } catch (IOException e) {
            e.printStackTrace();
        }

        //read ArqListaDigest
        try {
            File file = new File(filePath);
            BufferedReader br = new BufferedReader(new FileReader(file));
            Scanner reader = new Scanner(file);
            String line;
            while ((line = br.readLine()) != null) {
                String[] lineSplit = line.split(" ");
                String fileNameArq = Path.of(folderPath + "\\" + lineSplit[0]).toAbsolutePath().toString();
                System.out.println(fileNameArq);
                System.out.println(FileDic.get(fileNameArq));
                String hashDigest = bytes2Hex(FileDic.get(fileNameArq));
                String status = "";
                Collection<byte[]> auxDic = FileDic.values();
                int auxCounter = 0;

                //find duplicate digests in file
                Stream<MatchResult> auxFile = reader.findAll(hashDigest);

                //find duplicate digests in hashmap
                for (byte[] b : auxDic) {
                    String dig = bytes2Hex(b);
                    if (dig.contentEquals(hashDigest))
                        auxCounter++;
                }

                if (auxCounter > 1 || auxFile.count() > 1)
                    status = "(COLLISION)";
                else if (Arrays.stream(lineSplit).noneMatch(digestType::contentEquals)) {
                    status = "(NOT FOUND)";
                } else {
                    for (int i = 1; i < lineSplit.length - 1; i++) {
                        String digtype = lineSplit[i];
                        String digest = lineSplit[i + 1];
                        if (digest.contentEquals(hashDigest) && digtype.contentEquals(digestType)) {
                            status = "(OK)";
                            break;
                        }
                        else
                            status = "(NOT OK)";
                    }
                }
                System.out.println(fileNameArq + " " + digestType + " " + hashDigest + " " + status);
            }
            br.close();
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("File not found.");
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    public static void main(String[] args) throws NoSuchAlgorithmException {

        if (args.length < 3) {
            System.out.println("Missing parameters!\n Use DigestCalculator Tipo_Digest Caminho_ArqListaDigest Caminho_da_Pasta_dos_Arquivos");
            return;
        }
        if (!args[0].equalsIgnoreCase("MD5") && !args[0].equalsIgnoreCase("SHA-1")
            && !args[0].equalsIgnoreCase("SHA-256") && !args[0].equalsIgnoreCase("SHA-512")) {
            System.out.println("Invalid Digest Encoding!");
            return;
        }
        DigestCalculator DigCalc = new DigestCalculator(args[0], args[1], args[2]);
        DigCalc.VerifyDigests();
    }
}
