package urlphishingchecks.api;

import java.util.List;

public class PhishingResultDto {

    private final String        url;
    private final int           warningCount;
    private final String        verdict;
    private final List<Finding> findings;

    public PhishingResultDto(String url, int warningCount,
                             String verdict, List<Finding> findings) {
        this.url          = url;
        this.warningCount = warningCount;
        this.verdict      = verdict;
        this.findings     = findings;
    }

    public String        getUrl()          { return url; }
    public int           getWarningCount() { return warningCount; }
    public String        getVerdict()      { return verdict; }
    public List<Finding> getFindings()     { return findings; }

    // a container for one individual phishing warning
    public static class Finding {
        private final String label;
        private final String value;
        private final String severity;

        public Finding(String label, String value, String severity) {
            this.label    = label;
            this.value    = value;
            this.severity = severity;
        }

        public String getLabel()    { return label; }
        public String getValue()    { return value; }
        public String getSeverity() { return severity; }
    }
}