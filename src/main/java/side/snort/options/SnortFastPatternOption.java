package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004522000000000000000
 * <p>
 * The fast_pattern keyword is a content modifier that sets the content within a rule to be used with the fast pattern
 * matcher. The default behavior of fast pattern determination is to use the longest HTTP buffer content.
 * If no HTTP buffer is present, then the fast pattern is the longest content. Given this behavior,
 * it is useful if a shorter content is more "unique" than the longer content, meaning the shorter content is less
 * likely to be found in a packet than the longer content.
 */
public class SnortFastPatternOption extends SwallowedSnortOption {
    public SnortFastPatternOption(String value) {
        super(SnortOptionType.fast_pattern, value);
    }
}
