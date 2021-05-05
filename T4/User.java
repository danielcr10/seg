

public class User {

    private String Grupo;
    private String Name;
    private String PwdHash;
    private String PwdSalt;
    private String PublicKey;
    private int BlockTimer;
    private int LoginCounter;
    private String Certificate;

    public String getGrupo() {
        return Grupo;
    }

    public void setGrupo(String grupo) {
        Grupo = grupo;
    }

    public String getPwdHash() {
        return PwdHash;
    }

    public void setPwdHash(String pwdHash) {
        PwdHash = pwdHash;
    }

    public String getPwdSalt() {
        return PwdSalt;
    }

    public void setPwdSalt(String pwdSalt) {
        PwdSalt = pwdSalt;
    }

    public String getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(String publicKey) {
        PublicKey = publicKey;
    }

    public int getBlockTimer() {
        return BlockTimer;
    }

    public void setBlockTimer(int blockTimer) {
        BlockTimer = blockTimer;
    }

    public int getLoginCounter() {
        return LoginCounter;
    }

    public void setLoginCounter(int loginCounter) {
        LoginCounter = loginCounter;
    }

    public String getCertificate() {
        return Certificate;
    }

    public void setCertificate(String certificate) {
        Certificate = certificate;
    }

}
