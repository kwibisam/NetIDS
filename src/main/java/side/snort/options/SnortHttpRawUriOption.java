package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004518000000000000000
 *
 * The http_raw_uri keyword is a content modifier that restricts the search to the UNNORMALIZED request URI field .
 */
public class SnortHttpRawUriOption extends NotImplementedSnortOption {
    public SnortHttpRawUriOption(String value) {
        super(SnortOptionType.http_raw_uri, value);
    }
}
