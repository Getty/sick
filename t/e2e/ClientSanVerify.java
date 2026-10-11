// Used by t/e2e/client-san.sh: Java judges client certificate chains the
// way a JSSE server does - the PKIX trust manager's checkClientTrusted,
// which runs the PKIX path validation (name constraints included) and the
// TLS client checks of the leaf (extended key usage clientAuth, key usage).
//
//   java ClientSanVerify.java DIR
//
// DIR holds root_ca.crt and cases/*.pem (leaf first, then the
// intermediate). Prints "VERSION ..." and per case
// "RESULT <case> java accepted|refused <detail>". Revocation is not checked
// (the JDK default).

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class ClientSanVerify {
    static String oneLine(Throwable e) {
        StringBuilder s = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (s.length() > 0) s.append(" <- ");
            s.append(t.getClass().getSimpleName()).append(": ").append(t.getMessage());
        }
        return s.toString().replaceAll("\\s+", " ");
    }

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate root;
        try (InputStream in = Files.newInputStream(dir.resolve("root_ca.crt"))) {
            root = (X509Certificate) cf.generateCertificate(in);
        }
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("root", root);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(anchors);
        X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
        System.out.println("VERSION Java " + System.getProperty("java.runtime.version") + " (" + System.getProperty("java.vendor") + ")");

        List<Path> cases;
        try (Stream<Path> s = Files.list(dir.resolve("cases"))) {
            cases = s.filter(p -> p.toString().endsWith(".pem")).sorted().toList();
        }
        for (Path p : cases) {
            String name = p.getFileName().toString().replaceFirst("\\.pem$", "");
            try (InputStream in = Files.newInputStream(p)) {
                X509Certificate[] chain = cf.generateCertificates(in).toArray(new X509Certificate[0]);
                // the authType of a client is its key type
                tm.checkClientTrusted(chain, chain[0].getPublicKey().getAlgorithm());
                System.out.println("RESULT " + name + " java accepted ok");
            } catch (Exception e) {
                System.out.println("RESULT " + name + " java refused " + oneLine(e));
            }
        }
    }
}
