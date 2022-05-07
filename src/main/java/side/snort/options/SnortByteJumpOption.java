package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004532000000000000000
 * <p>
 * The byte_jump keyword allows rules to be written for length encoded protocols trivially. By having an option that
 * reads the length of a portion of data, then skips that far forward in the packet, rules can be written that skip
 * over specific portions of length-encoded protocols and perform detection in very specific locations.
 */
public class SnortByteJumpOption extends NotImplementedSnortOption {
    public SnortByteJumpOption(String value) {
        super(SnortOptionType.byte_jump, value);
    }
}
