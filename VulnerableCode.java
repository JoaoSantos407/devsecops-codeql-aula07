import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ATENÇÃO:
 * ==========================================================
 * ESTE CÓDIGO É INTENCIONALMENTE VULNERÁVEL.
 *
 * Foi criado APENAS para fins educacionais, para que
 * ferramentas de SAST (CodeQL, SonarQube, etc.) e de DAST
 * possam identificar problemas de segurança.
 *
 * NÃO USE NADA DISSO EM CÓDIGO REAL.
 * ==========================================================
 */
public class VulnerableCode {

    // 1) CREDENCIAIS EM CÓDIGO (HARD-CODED CREDENTIALS)
    // Problema: URL, usuário e senha do banco expostos no código-fonte.
    private static final String DB_URL      = "jdbc:mysql://localhost:3306/minha_aplicacao";
    private static final String DB_USER     = "root";
    private static final String DB_PASSWORD = "senha_super_secreta";

    /**
     * Simula um login totalmente inseguro.
     *
     * Vulnerabilidades:
     * - SQL Injection (concatenação direta).
     * - Uso de Statement.
     * - Exposição de stack trace em logs.
     */
    public boolean loginInseguro(String username, String password) {
        Connection conn = null;
        Statement stmt  = null;
        ResultSet rs    = null;

        try {
            // 2) CONEXÃO COM CREDENCIAIS HARDCODED
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 3) SQL INJECTION
            // username e password são concatenados diretamente na query.
            String sql = "SELECT * FROM usuarios WHERE username = '"
                    + username + "' AND password = '" + password + "'";

            stmt = conn.createStatement();
            rs   = stmt.executeQuery(sql);

            // 4) POSSÍVEL VAZAMENTO DE INFORMAÇÃO
            // Poderia vazar se retornasse dados sensíveis do usuário.
            return rs.next();

        } catch (Exception e) {
            // 5) TRATAMENTO GENÉRICO DE EXCEÇÃO + STACKTRACE
            e.printStackTrace();
            return false;

        } finally {
            try {
                if (rs   != null) rs.close();
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
                // Ignorando exceções silenciosamente (má prática)
            }
        }
    }

    /**
     * Busca usuários por termo de pesquisa.
     *
     * Vulnerabilidade: SQL Injection pela concatenação de searchTerm.
     */
    public void buscarUsuarios(String searchTerm) {
        Connection conn = null;
        Statement stmt  = null;

        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 6) SQL INJECTION EM CONSULTA DE BUSCA
            String sql = "SELECT * FROM usuarios WHERE nome LIKE '%" + searchTerm + "%'";
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                System.out.println("Usuário encontrado: " + rs.getString("nome"));
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Armazena senha usando algoritmo fraco (MD5).
     *
     * Vulnerabilidade:
     * - MD5 sem salt, inseguro.
     */
    public String armazenarSenhaInsegura(String senhaPlano) {
        try {
            // 7) USO DE MD5 (ALGORITMO FRACO)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(senhaPlano.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            String hashInseguro = sb.toString();
            System.out.println("Senha armazenada (hash inseguro MD5): " + hashInseguro);
            return hashInseguro;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Gera HTML de perfil sem sanitização de entrada.
     *
     * Vulnerabilidade:
     * - XSS (Cross-Site Scripting), pois o valor de "nome"
     *   é injetado diretamente no HTML.
     */
    public String gerarPaginaPerfil(String nome) {
        // 8) XSS – nome é inserido diretamente no HTML
        String html =
                "<html>" +
                "<head><title>Perfil do Usuário</title></head>" +
                "<body>" +
                "<h1>Bem-vindo, " + nome + "!</h1>" +
                "<p>Esse é o seu painel.</p>" +
                "</body>" +
                "</html>";

        return html;
    }

    /**
     * Método main para facilitar testes básicos.
     */
    public static void main(String[] args) {
        VulnerableCode app = new VulnerableCode();

        // Login inseguro
        System.out.println("Tentando login inseguro...");
        boolean autenticado = app.loginInseguro("admin", "admin123");
        System.out.println("Login realizado? " + autenticado);

        // Busca insegura
        System.out.println("\nBuscando usuários com termo inseguro...");
        app.buscarUsuarios("teste' OR '1'='1");

        // Armazenamento inseguro de senha
        System.out.println("\nArmazenando senha com MD5 (inseguro)...");
        app.armazenarSenhaInsegura("minha_senha_fraca");

        // XSS
        System.out.println("\nGerando HTML de perfil (possível XSS)...");
        String pagina = app.gerarPaginaPerfil("<script>alert('XSS');</script>");
        System.out.println(pagina);
    }
}
