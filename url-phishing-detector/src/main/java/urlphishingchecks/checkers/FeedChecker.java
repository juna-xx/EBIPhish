package urlphishingchecks.checkers;

import urlphishingchecks.PhishingResult;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

public class FeedChecker {


    private final String openPhishFilePath;
    private final String safeBrowsingApiKey;
    private Set<String> openPhishUrls;

    public FeedChecker(String openPhishFilePath, String safeBrowsingApiKey) {
        this.openPhishFilePath  = openPhishFilePath;
        this.safeBrowsingApiKey = safeBrowsingApiKey;
    }

    public void check(String targetUrl, PhishingResult result) {
        result.add("Listed in OpenPhish feed",         checkOpenPhish(targetUrl));
        result.add("Flagged by Google Safe Browsing",  checkGoogleSafeBrowsing(targetUrl));
    }

    private boolean checkOpenPhish(String targetUrl) {
        if (openPhishUrls == null) {
            openPhishUrls = loadOpenPhishFeed();
        }
        return openPhishUrls.contains(normalise(targetUrl));
    }

    private Set<String> loadOpenPhishFeed() {
        Set<String> urls = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(
                Paths.get(openPhishFilePath), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) urls.add(normalise(line));
            }
            System.out.println("[OpenPhish] Feed loaded: " + urls.size() + " entries.");
        } catch (IOException e) {
            System.err.println("[OpenPhish] Could not read feed file: " + e.getMessage());
        }
        return urls;
    }

    private String normalise(String url) {
        return url.toLowerCase().stripTrailing().replaceAll("/$", "");
    }

    private boolean checkGoogleSafeBrowsing(String targetUrl) {
        if (safeBrowsingApiKey == null || safeBrowsingApiKey.equals("YOUR_GOOGLE_SAFE_BROWSING_API_KEY")) {
            System.err.println("[SafeBrowsing] No API key configured – skipping.");
            return false;
        }

        try {
            
            String encodedUrl = java.net.URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
            String endpoint   = "https://safebrowsing.googleapis.com/v5alpha1/urls:search"
                + "?key=" + safeBrowsingApiKey
                + "&urls=" + encodedUrl; 

            URL url = new URL(endpoint);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("Accept", "application/json");
            con.setConnectTimeout(5_000);
            con.setReadTimeout(10_000);
            

            int status = con.getResponseCode();
            if (status != 200) {
                StringBuilder errorBody = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) errorBody.append(line);
                }
                System.err.println("[SafeBrowsing] HTTP " + status + " – " + errorBody.toString());
                return false;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }

            String response = sb.toString();

            // Empty threats array = safe, non-empty = flagged
            return response.contains("\"threats\"") && !response.contains("\"threats\":[]");

        } catch (Exception e) {
            System.err.println("[SafeBrowsing] Check failed: " + e.getMessage());
            return false;
        }
    }

}