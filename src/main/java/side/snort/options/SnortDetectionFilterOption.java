package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node34.html#SECTION00477000000000000000
 * <p>
 * detection_filter defines a rate which must be exceeded by a source or destination host before a rule can generate
 * an event.
 */
public class SnortDetectionFilterOption extends NotImplementedSnortOption {
    public SnortDetectionFilterOption(String value) {
        super(SnortOptionType.detection_filter, value);
    }
}
