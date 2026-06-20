package urlphishingchecks.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class PhishingController {

    private final PhishingService service;

    public PhishingController(PhishingService service) {
        this.service = service;
    }

    // pre-load endpoint
    @GetMapping("/check")
    public ResponseEntity<PhishingResultDto> check(@RequestParam String url) {
        if (url == null || url.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        long start = System.nanoTime();

        PhishingResultDto response = service.analyse(url);

        long end = System.nanoTime();
        double seconds = (end - start) / 1_000_000_000.0;

        System.out.printf("[/api/check] %.3f seconds%n", seconds);
    
        return ResponseEntity.ok(response);
    }

    // post-load endpoint, receives page URL + extracted links from the extension
    @PostMapping("/check-page")
    public ResponseEntity<PhishingResultDto> checkPage(@RequestBody PageScanRequest request) {
        if (request.url() == null || request.url().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        long start = System.nanoTime();
        
        PhishingResultDto response = service.analysePage(request.url(), request.pageLinks());

        long end = System.nanoTime();
        double seconds = (end - start) / 1_000_000_000.0;

        System.out.printf("[/api/check-page] %.3f seconds%n", seconds);
        return ResponseEntity.ok(response);
    }
    
    @Value("${groq.api.key}")
    private String apiKey;
    @GetMapping("/config/groq-key")
    public String getGroqKey() {
        return apiKey;
    }

    // Request body model - Java record maps directly from JSON
    public record PageScanRequest(String url, List<String> pageLinks) {}
}