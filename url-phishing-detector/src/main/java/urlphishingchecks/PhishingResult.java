package urlphishingchecks;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PhishingResult {

    private final String url;
    private final List<String[]> findings = new ArrayList<>();
    private int warningCount = 0;

    public PhishingResult(String url) {
        this.url = url;
    }

    public void add(String label, boolean suspicious) {
        if (suspicious) warningCount++;
        findings.add(new String[]{
            label,
            suspicious ? "YES ⚠" : "No",
            suspicious ? "WARN" : "OK"
        });
    }

    public void addInfo(String label, String value) {
        findings.add(new String[]{label, value, "INFO"});
    }

    public void addBlock(String header, String body) {
        findings.add(new String[]{header, body, "BLOCK"});
    }

    public List<String[]> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public int getWarningCount() {
        return warningCount;
    }

    public String getVerdict() {
        if (warningCount == 0) return "LIKELY SAFE";
        if (warningCount <= 2) return "SUSPICIOUS – review carefully";
        return "HIGH RISK – probable phishing";
    }

    public String buildReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n--- Phishing Analysis Report ---\n");
        sb.append("URL : ").append(url).append("\n\n");

        for (String[] f : findings) {
            switch (f[2]) {
                case "WARN"  -> sb.append(String.format("  [WARN] %-45s %s%n", f[0], f[1]));
                case "OK"    -> sb.append(String.format("  [ OK ] %-45s %s%n", f[0], f[1]));
                case "INFO"  -> sb.append(String.format("  [INFO] %-45s %s%n", f[0], f[1]));
                case "BLOCK" -> {
                    sb.append("\n  --- ").append(f[0]).append(" ---\n");
                    sb.append(f[1]).append("\n");
                }
            }
        }

        sb.append("\n==============================================\n");
        sb.append("  Total warnings: ").append(warningCount).append("\n");
        sb.append("  Verdict : ").append(getVerdict()).append("\n");
        sb.append("==============================================\n");
        return sb.toString();
    }
}