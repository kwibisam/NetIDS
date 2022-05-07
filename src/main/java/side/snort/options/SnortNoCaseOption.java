package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00455000000000000000
 * <p>
 * The nocase keyword allows the rule writer to specify that the Snort should look for the specific pattern,
 * ignoring case. nocase modifies the previous content keyword in the rule.
 */
public class SnortNoCaseOption extends SwallowedSnortOption {
    public SnortNoCaseOption(String value) {
        super(SnortOptionType.nocase, value);
    }
}
