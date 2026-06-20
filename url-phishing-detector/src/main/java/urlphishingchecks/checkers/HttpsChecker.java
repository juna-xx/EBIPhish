package urlphishingchecks.checkers;

import urlphishingchecks.PhishingResult;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class HttpsChecker {

    public void check(String urlString, PhishingResult result) {
        boolean https = urlString.toLowerCase().startsWith("https://");
        result.add("Not using HTTPS", !https);

        if (!https) {
            result.addInfo("SSL / TLS check", "Skipped (no HTTPS)");
            return;
        }

        try {
            URL url = new URL(urlString);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setConnectTimeout(5_000);
            con.setReadTimeout(10_000);
            con.connect();

            boolean certValid = false;
            try {
                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    if (cert instanceof X509Certificate x509) {
                        x509.checkValidity();
                        certValid = true;
                        break;
                    }
                }
            } catch (Exception e) { }

            result.add("SSL certificate invalid or expired", !certValid);

            String cipher = con.getCipherSuite();
            result.addInfo("Cipher suite", cipher);
            result.addInfo("TLS version (inferred)", inferTlsVersion(cipher));
            analyseCipher(cipher, result);

            con.disconnect();

        } catch (Exception e) {
            result.addInfo("SSL / TLS check", "Failed: " + e.getMessage());
        }
    }

    private String inferTlsVersion(String cipher) {
        String c = cipher.toUpperCase();
        if (c.startsWith("TLS_AES") || c.startsWith("TLS_CHACHA20")) return "TLS 1.3 (likely)";
        if (c.contains("_GCM_") || c.contains("_ECDHE_"))            return "TLS 1.2 (likely)";
        if (c.startsWith("SSL"))                                      return "SSL – INSECURE";
        return "Unknown";
    }

    private void analyseCipher(String cipher, PhishingResult result) {
        String c = cipher.toUpperCase();
        result.add("Broken encryption (RC4 / DES)",  c.contains("RC4") || c.contains("DES"));
        result.add("Weak cipher (3DES)",              c.contains("3DES"));
        result.add("Insecure hash (MD5)",             c.contains("MD5"));
        result.add("Weak hash (SHA-1)",               c.contains("SHA1"));
        result.add("Insecure protocol (SSL)",         c.startsWith("SSL"));
        result.add("No forward secrecy (static RSA)", c.contains("RSA") && !c.contains("ECDHE"));

        if (c.contains("GCM") || c.contains("CHACHA20"))
            result.addInfo("Encryption quality", "Modern (GCM / ChaCha20)");
        if (c.contains("ECDHE"))
            result.addInfo("Forward secrecy", "Supported (ECDHE)");
    }
}