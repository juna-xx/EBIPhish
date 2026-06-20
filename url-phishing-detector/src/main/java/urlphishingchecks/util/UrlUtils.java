package urlphishingchecks.util;

import java.net.URL;

public final class UrlUtils {

    private UrlUtils() {}

    public static String getHost(String urlString) {
    try {
        if (urlString == null) return null;

        urlString = urlString.trim();

        if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
            urlString = "https://" + urlString;
        }

        return new URL(urlString).getHost();
    } catch (Exception e) {
        return null;
    }
}

    public static boolean isIPAddress(String host) {
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    public static boolean hasTooManySubdomains(String host) {
        return host.split("\\.").length > 4;
    }
}