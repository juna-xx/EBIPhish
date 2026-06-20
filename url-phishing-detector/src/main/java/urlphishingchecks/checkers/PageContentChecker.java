package urlphishingchecks.checkers;

import urlphishingchecks.PhishingResult;

import java.net.URL;
import java.util.List;

/**
 * Scans links extracted from the visited page.
 * For each external link found, runs FeedChecker and UnicodeChecker.
 * Does NOT make WHOIS or HTTPS connections per link, too slow for bulk scanning.
 *
 * Called by PhishingService.analysePage() via the POST /api/check-page endpoint.
 */
public class PageContentChecker {

    private static final int MAX_LINKS_TO_SCAN = 50; // cap to avoid slow responses

    private final FeedChecker    feedChecker;
    private final UnicodeChecker unicodeChecker = new UnicodeChecker();

    public PageContentChecker(FeedChecker feedChecker) {
        // Reuses the same FeedChecker instance (OpenPhish already cached in memory)
        this.feedChecker = feedChecker;
    }

    public void check(String pageUrl, List<String> pageLinks, PhishingResult result) {
        if (pageLinks == null || pageLinks.isEmpty()) {
            result.addInfo("Page links scanned", "None found");
            return;
        }

        String pageDomain = extractDomain(pageUrl);

        // Only scan external links, links on the same domain are not of interest
        List<String> externalLinks = pageLinks.stream()
                .filter(l -> l.startsWith("http"))
                .filter(l -> !extractDomain(l).equals(pageDomain))
                .distinct()
                .limit(MAX_LINKS_TO_SCAN)
                .toList();

        result.addInfo("External links found", String.valueOf(externalLinks.size()));

        if (externalLinks.isEmpty()) {
            result.addInfo("Page links scanned", "No external links detected");
            return;
        }

        int suspiciousLinkCount = 0;

        for (String link : externalLinks) {
            PhishingResult linkResult = new PhishingResult(link);

            // Run feed check on the link
            feedChecker.check(link, linkResult);

            // Run Unicode check on the link
            unicodeChecker.check(link, linkResult);

            if (linkResult.getWarningCount() > 0) {
                suspiciousLinkCount++;
            }
        }

        result.add("Suspicious links found on page",  suspiciousLinkCount > 0);

        if (suspiciousLinkCount > 0) {
            result.addInfo("Suspicious link count", suspiciousLinkCount + " of " + externalLinks.size() + " external links");
        }
    }

    private String extractDomain(String url) {
        try {
            String host = new URL(url).getHost();
            String[] parts = host.split("\\.");
            if (parts.length >= 2)
                return parts[parts.length - 2] + "." + parts[parts.length - 1];
            return host;
        } catch (Exception e) {
            return "";
        }
    }
}