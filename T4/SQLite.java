import java.sql.*;

public class SQLite {

    private final String url;
    private Connection conn;

    public SQLite(String fileName) {
        String url = "jdbc:sqlite:" + fileName;
        this.url = url;

        try (Connection conn = DriverManager.getConnection(url)) {
            this.conn = conn;
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("A new database has been created.");
            }

        } catch (SQLException e) {
            this.conn = null;
            System.out.println(e.getMessage());
        }
    }

    public void insertUsuario(int id, String email, String grp, String salt, String hash, String cert) {
        String sql = "INSERT INTO usuarios (id,email,group,salt,hash,cert) VALUES(?,?,?,?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setString(2, email);
            pstmt.setString(3, grp);
            pstmt.setString(4, salt);
            pstmt.setString(5, hash);
            pstmt.setString(6, cert);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void updateUsuario(int id, String email, String grp, String salt, String hash, String cert) {
        String sql = "UPDATE usuarios SET email=?,group=?,salt=?,hash=?,cert=? WHERE id=?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(6, id);
            pstmt.setString(1, email);
            pstmt.setString(2, grp);
            pstmt.setString(3, salt);
            pstmt.setString(4, hash);
            pstmt.setString(5, cert);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertRegistro(int id, int uid, String timestamp) {
        String sql = "INSERT INTO registros (id,userid,timestamp) VALUES(?,?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setInt(2, uid);
            pstmt.setString(3, timestamp);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertMensagem(int id, String msg) {
        String sql = "INSERT INTO mensagem (id,message) VALUES(?,?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setString(2, msg);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertGrupo(int id, String msg) {
        String sql = "INSERT INTO grupos (id) VALUES(?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void createTables() {
        // SQL statement for creating a new table
        String sql = "CREATE TABLE IF NOT EXISTS grupos (\n"
                + "	id integer PRIMARY KEY\n"
                + ");\n";
        sql += "CREATE TABLE IF NOT EXISTS usuarios (\n"
                + "	id integer PRIMARY KEY,\n"
                + "	email text NOT NULL,\n"
                + "	group integer,\n"
                + "	salt text,\n"
                + "	hash text,\n"
                + "	cert text,\n"
                + " FOREIGN KEY(group) REFERENCES grupos(id)"
                + ");\n";
        sql += "CREATE TABLE IF NOT EXISTS mensagens (\n"
                + "	id integer PRIMARY KEY,\n"
                + "	message text\n"
                + ");\n";
        sql += "CREATE TABLE IF NOT EXISTS registros (\n"
                + "	id integer PRIMARY KEY,\n"
                + "	userid integer,\n"
                + "	timestamp text,\n"
                + " FOREIGN KEY(id) REFERENCES mensagens(id),"
                + " FOREIGN KEY(userid) REFERENCES user(id)"
                + ");\n";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Tables created successfully");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
}
