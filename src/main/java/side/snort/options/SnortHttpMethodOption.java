package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004516000000000000000
 *
 *  The http_method keyword is a content modifier that restricts the search to the extracted Method from a HTTP client
 *  request.
 */
public class SnortHttpMethodOption extends NotImplementedSnortOption {
    public SnortHttpMethodOption(String value) {
        super(SnortOptionType.http_method, value);
    }
}
