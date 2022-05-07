package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00468000000000000000
 * <p>
 * The flags keyword is used to check if specific TCP flag bits are present.
 */
public class SnortFlagsOption extends NotImplementedSnortOption {
    public SnortFlagsOption(String value) {
        super(SnortOptionType.flags, value);
    }
}
