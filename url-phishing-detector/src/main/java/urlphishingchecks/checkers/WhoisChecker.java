package urlphishingchecks.checkers;

import urlphishingchecks.PhishingResult;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

public class WhoisChecker {

    private static final String API_BASE   = "https://api.api-ninjas.com/v1/whois?domain=";
    private static final int    TIMEOUT_MS = 8_000;

    private final String apiKey;
    private final long   newDomainThresholdDays;

    public WhoisChecker(String apiKey, long newDomainThresholdDays) {
        this.apiKey                 = apiKey;
        this.newDomainThresholdDays = newDomainThresholdDays;
    }

    public void check(String domain, PhishingResult result) {
        if (apiKey == null || apiKey.equals("NINJA_API_KEY")) {
            result.addInfo("WHOIS", "Skipped — no API Ninjas key configured.");
            return;
        }

        String json = callApi(domain);

        if (json == null || json.isBlank() || json.equals("{}")) {
            result.addInfo("WHOIS", "No data returned for: " + domain);
            System.out.println("[WHOIS RAW RESPONSE] " + json);
            return;
        }

        String registrar = extractString(json, "registrar");
        if (registrar != null) result.addInfo("Registrar", registrar);

        /*String nameServers = extractNameServers(json);
        if (nameServers != null) result.addInfo("Name servers", nameServers);*/

        Long expiryTs = extractLong(json, "expiration_date");
        if (expiryTs != null) result.addInfo("Domain expiry", toLocalDate(expiryTs).toString());

        Long creationTs = extractLong(json, "creation_date");
        if (creationTs != null) {
            LocalDate created = toLocalDate(creationTs);
            long ageDays = ChronoUnit.DAYS.between(created, LocalDate.now(ZoneOffset.UTC));
            result.addInfo("Domain created", created + " (" + ageDays + " days ago)");
            result.add("Domain is newly registered (< " + newDomainThresholdDays + " days)",
                       ageDays < newDomainThresholdDays);
        } else {
            result.addInfo("Domain created", "Not found in WHOIS response");
        }
    }

    private String callApi(String domain) {
        try {
            URL url = new URL(API_BASE + domain);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("X-Api-Key", apiKey);
            con.setConnectTimeout(TIMEOUT_MS);
            con.setReadTimeout(TIMEOUT_MS);

            if (con.getResponseCode() != 200) {
                System.err.println("[WHOIS] API Ninjas returned HTTP " + con.getResponseCode());
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }
            return sb.toString();

        } catch (Exception e) {
            System.err.println("[WHOIS] Request failed: " + e.getMessage());
            return null;
        }
    }
 // finds a string value associated with a json key
    private String extractString(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + search.length());
        if (colon < 0) return null;
        int openQuote = json.indexOf('"', colon + 1);
        if (openQuote < 0) return null;
        int closeQuote = json.indexOf('"', openQuote + 1);
        if (closeQuote < 0) return null;
        return json.substring(openQuote + 1, closeQuote);
    }
// extracts a numeric value from json - try to replace them with jackson
    private Long extractLong(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + search.length());
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        if (start == end) return null;
        try { return Long.parseLong(json.substring(start, end)); }
        catch (NumberFormatException e) { return null; }
    }

    /* private String extractNameServers(String json) {
        String search = "\"name_servers\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + search.length());
        if (colon < 0) return null;
        int afterColon = colon + 1;
        while (afterColon < json.length() && json.charAt(afterColon) == ' ') afterColon++;
        if (json.charAt(afterColon) == '[') {
            int closeArr = json.indexOf(']', afterColon);
            if (closeArr < 0) return null;
            return json.substring(afterColon + 1, closeArr)
                       .replaceAll("\"", "").replaceAll(",\\s*", ", ").trim();
        } else if (json.charAt(afterColon) == '"') {
            return extractString(json, "name_servers");
        }
        return null;
    } */

    private LocalDate toLocalDate(long unixTimestamp) {
        return Instant.ofEpochSecond(unixTimestamp).atZone(ZoneOffset.UTC).toLocalDate();
    }
}