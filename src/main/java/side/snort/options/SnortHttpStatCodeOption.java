package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004519000000000000000
 *
 * The http_stat_code keyword is a content modifier that restricts the search to the extracted Status code field from a
 * HTTP server response.
 */
public class SnortHttpStatCodeOption extends NotImplementedSnortOption {
    protected SnortHttpStatCodeOption(String value) {
        super(SnortOptionType.http_stat_code, value);
    }
}
