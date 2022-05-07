package side.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004528000000000000000
 * <p>
 * This option sets the cursor used for detection to one of the following buffers:
 * 1. When the traffic being detected is HTTP it sets the buffer to,
 * a. HTTP response body (without chunking/compression/normalization)
 * b. HTTP de-chunked response body
 * c. HTTP decompressed response body (when inspect_gzip is turned on)
 * d. HTTP normalized response body (when normalized_javascript is turned on)
 * e. HTTP UTF normalized response body (when normalize_utf is turned on)
 * f. All of the above
 * 2. When the traffic being detected is SMTP/POP/IMAP it sets the buffer to,
 * a. SMTP/POP/IMAP data body (including Email headers and MIME when decoding is turned off)
 * b. Base64 decoded MIME attachment (when b64_decode_depth is greater than -1)
 * c. Non-Encoded MIME attachment (when bitenc_decode_depth is greater than -1)
 * d. Quoted-Printable decoded MIME attachment (when qp_decode_depth is greater than -1)
 * e. Unix-to-Unix decoded attachment (when uu_decode_depth is greater than -1)
 * 3. If it is not set by 1 and 2, it will be set to the payload.
 */
public class SnortFileDataOption extends NotImplementedSnortOption {
    public SnortFileDataOption(String value) {
        super(SnortOptionType.file_data, value);
    }
}
