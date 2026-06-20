package urlphishingchecks.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import urlphishingchecks.PhishingResult;
import urlphishingchecks.checkers.*;
import urlphishingchecks.util.UrlUtils;

import java.util.List;

@Service
public class PhishingService {

    private final FeedChecker        feedChecker;
    private final WhoisChecker       whoisChecker;
    private final PageContentChecker pageContentChecker;

    private final HttpsChecker   httpsChecker   = new HttpsChecker();
    private final UnicodeChecker unicodeChecker = new UnicodeChecker();

    public PhishingService(
            @Value("${app.openphish.feed-path}")                String openPhishPath,
            @Value("${app.api-key.google-safe-browsing}")       String safeBrowsingKey,
            @Value("${app.api-key.api-ninjas}")                 String apiNinjasKey,
            @Value("${app.whois.new-domain-threshold-days:90}") long domainAgeThreshold
    ) {
        this.feedChecker        = new FeedChecker(openPhishPath, safeBrowsingKey);
        this.whoisChecker       = new WhoisChecker(apiNinjasKey, domainAgeThreshold);
        this.pageContentChecker = new PageContentChecker(feedChecker); // reuses feedChecker
    }

    // /api/check
    public PhishingResultDto analyse(String url) {
        PhishingResult result = new PhishingResult(url);
        String host = UrlUtils.getHost(url);

        feedChecker.check(url, result);
        httpsChecker.check(url, result);
        whoisChecker.check(host, result);
        unicodeChecker.check(url, result);

        result.add("IP address instead of domain",      UrlUtils.isIPAddress(host));
        result.add("Too many subdomains (>4 labels)",   UrlUtils.hasTooManySubdomains(host));
        result.add("Suspicious URL length (>75 chars)", url.length() > 75);

        List<PhishingResultDto.Finding> findings = result.getFindings().stream()
                .map(f -> new PhishingResultDto.Finding(f[0], f[1], f[2]))
                .toList();

        return new PhishingResultDto(url, result.getWarningCount(), result.getVerdict(), findings);
    }

    // method called by POST /api/check-page
    public PhishingResultDto analysePage(String url, List<String> pageLinks) {
        PhishingResult result = new PhishingResult(url);
        String host = UrlUtils.getHost(url);
        
        if (host == null || host.isBlank() || host.equals("invalid")) {
            result.addInfo("WHOIS", "Skipped — invalid host: " + host);
        } else {
            whoisChecker.check(host, result);
        }

        // All existing checks on the page URL itself
        feedChecker.check(url, result);
        httpsChecker.check(url, result);
        // whoisChecker.check(host, result);
        unicodeChecker.check(url, result);

        result.add("IP address instead of domain",      UrlUtils.isIPAddress(host));
        result.add("Too many subdomains (>4 labels)",   UrlUtils.hasTooManySubdomains(host));
        result.add("Suspicious URL length (>75 chars)", url.length() > 75);

        // scan links found on the page
        pageContentChecker.check(url, pageLinks, result);

        List<PhishingResultDto.Finding> findings = result.getFindings().stream()
                .map(f -> new PhishingResultDto.Finding(f[0], f[1], f[2]))
                .toList();

        return new PhishingResultDto(url, result.getWarningCount(), result.getVerdict(), findings);
    }
}