package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004512000000000000000
 *
 * The http_cookie keyword is a content modifier that restricts the search to the extracted Cookie Header field
 * (excluding the header name itself and the CRLF terminating the header line) of a HTTP client request or a HTTP server
 * response (per the configuration of HttpInspect [*]). The Cookie buffer does not include the header names
 * (Cookie: for HTTP requests or Set-Cookie: for HTTP responses) or leading spaces and the CRLF terminating the header
 * line. These are included in the HTTP header buffer.
 */
public class SnortHttpCookieOption extends NotImplementedSnortOption {
    protected SnortHttpCookieOption(String value) {
        super(SnortOptionType.http_cookie, value);
    }
}
