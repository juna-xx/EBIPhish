package urlphishingchecks.checkers;

import urlphishingchecks.PhishingResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class UnicodeChecker {

    private static final Set<Character> INVISIBLE_CHARS = Set.of(
            '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u180E'
    );

    private static final Set<Character> HOMOGLYPHS = Set.of(
            '\u0430', '\u0435', '\u043E', '\u0440', '\u0441', '\u0455',
            '\u03BF', '\uFF41', '\uFF45'
    );

    public void check(String url, PhishingResult result) {
        List<String> issues = detectSuspiciousCharacters(url);
        result.add("Hidden / invisible Unicode characters", containsType(issues, "Invisible"));
        result.add("Control characters in URL",             containsType(issues, "Control"));
        result.add("Homoglyph characters detected",         containsType(issues, "Homoglyph"));
        result.add("Mixed Latin + Cyrillic scripts (IDN homograph)", hasMixedScripts(url));
        if (!issues.isEmpty())
            result.addBlock("Unicode character detail", String.join("\n", issues));
    }

    private List<String> detectSuspiciousCharacters(String url) {
        List<String> issues = new ArrayList<>();
        for (char c : url.toCharArray()) {
            if (INVISIBLE_CHARS.contains(c))
                issues.add("  Invisible character : U+" + hex(c) + "  (" + Character.getName(c) + ")");
            else if (isControlChar(c))
                issues.add("  Control character   : U+" + hex(c));
            else if (HOMOGLYPHS.contains(c))
                issues.add("  Homoglyph           : U+" + hex(c) + "  '" + c + "'  (" + Character.getName(c) + ")");
        }
        return issues;
    }

    private boolean hasMixedScripts(String url) {
        boolean latin = false, cyrillic = false;
        for (char c : url.toCharArray()) {
            Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
            if (block == Character.UnicodeBlock.BASIC_LATIN) latin    = true;
            if (block == Character.UnicodeBlock.CYRILLIC)    cyrillic = true;
        }
        return latin && cyrillic;
    }

    private boolean isControlChar(char c) { return (c >= 0 && c <= 31) || c == 127; }
    private boolean containsType(List<String> issues, String type) {
        return issues.stream().anyMatch(s -> s.contains(type));
    }
    private String hex(char c) { return String.format("%04X", (int) c); }

    /**
 * Public wrapper so PageContentChecker can scan individual page links.
 */
    public List<String> detectPublic(String url) {
        return detectSuspiciousCharacters(url);
    }

}