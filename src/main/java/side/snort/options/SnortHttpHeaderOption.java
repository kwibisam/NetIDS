package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004514000000000000000
 * <p>
 * The http_header keyword is a content modifier that restricts the search to the extracted Header fields of a HTTP
 * client request or a HTTP server response (per the configuration of HttpInspect [*]).
 */
public class SnortHttpHeaderOption extends NotImplementedSnortOption {
    public SnortHttpHeaderOption(String value) {
        super(SnortOptionType.http_header, value);
    }
}
