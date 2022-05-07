package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004511000000000000000
 * <p>
 * The http_client_body keyword is a content modifier that restricts the search to the body of an HTTP client request.
 * As this keyword is a modifier to the previous content keyword, there must be a content in the rule before
 * 'http_client_body' is specified.
 */
public class SnortHttpClientBodyOption extends NotImplementedSnortOption {
    public SnortHttpClientBodyOption(String value) {
        super(SnortOptionType.http_client_body, value);
    }
}
