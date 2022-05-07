package side.snort.options;

import side.PacketInfo;
import side.snort.SnortRule;
import side.utils.PeakableIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;

public abstract class SnortOption {
    protected static Logger logger = LoggerFactory.getLogger(SnortOption.class);

    protected final SnortOptionType type;
    protected final String value;

    protected SnortOption(SnortOptionType type, String value) {
        super();
        this.type = type;
        this.value = value;
    }

    public static List<SnortOption> asSnortOptions(String value, SnortRule rule) throws Exception {
        return parse(value, rule);
    }

    private static List<SnortOption> parse(String value, SnortRule rule) throws Exception {
        List<SnortOption> out = new LinkedList<>();

        StringBuilder accum = new StringBuilder();
        boolean inQuotes = false;
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"':
                    inQuotes = !inQuotes;
                    break;
                case ';':
                    if (inQuotes) {
                        accum.append(c);
                    } else {
                        try {
                            SnortOption option = parseOption(accum.toString().trim(), rule);
                            if (option != null) {
                                out.add(option);
                            }
                        } catch (Exception e) {
                            logger.error("Could not parse rule {}", accum, e);
                        }
                        accum.setLength(0);
                    }
                    break;
                default:
                    accum.append(c);
            }
        }
        if (accum.length() > 0) {
            SnortOption option = parseOption(accum.toString().trim(), rule);
            if (option != null) {
                out.add(option);
            }
        }
        return out;
    }

    private static SnortOption parseOption(String option, SnortRule rule) throws Exception {
        try {
            String typeStr = option;
            String value = null;
            if (option.contains(":")) {
                String[] parts = option.split(":", 2);
                typeStr = parts[0].trim();
                value = parts[1].trim();
            }
            SnortOptionType type = SnortOptionType.valueOf(typeStr);
            switch (type) {
                case content:
                    return new SnortContentOption(value);
                case isdataat:
                    return new SnortIsDataAtOption(value);
                case nocase:
                    return new SnortNoCaseOption(value);
                case flow:
                    return new SnortFlowOption(value);
                case urilen:
                    return new SnortUriLenOption(value);
                case fast_pattern:
                    return new SnortFastPatternOption(value);
                case pcre:
                    return new SnortPcreOption(value);
                case http_header:
                    return new SnortHttpHeaderOption(value);
                case http_method:
                    return new SnortHttpMethodOption(value);
                case http_client_body:
                    return new SnortHttpClientBodyOption(value);
                case http_uri:
                    return new SnortHttpUriOption(value);
                case http_cookie:
                    return new SnortHttpCookieOption(value);
                case http_stat_code:
                    return new SnortHttpStatCodeOption(value);
                case http_raw_uri:
                    return new SnortHttpRawUriOption(value);
                case activated_by:
                    return new SnortActivatedByOption(value);
                case activates:
                    return new SnortActivatesOption(value);
                case itype:
                    return new SnortITypeOption(value);
                case msg:
                    rule.setMsg(value);
                    return null;
                case sid:
                    rule.setSid(value);
                    return null;
                case rev:
                    rule.setRev(value);
                    return null;
                case metadata:
                    rule.setMetadata(value);
                    return null;
                case classtype:
                    rule.setClassType(value);
                    return null;
                case reference:
                    rule.setReference(value);
                    return null;
                case flags:
                    return new SnortFlagsOption(value);
                case flowbits:
                    return new SnortFlowbitsOption(value);
                case file_data:
                    return new SnortFileDataOption(value);
                case depth:
                    return new SnortDepthOption(value);
                case dsize:
                    return new SnortDSizeOption(value);
                case within:
                    return new SnortWithinOption(value);
                case distance:
                    return new SnortDistanceOption(value);
                case byte_jump:
                    return new SnortByteJumpOption(value);
                case detection_filter:
                    return new SnortDetectionFilterOption(value);
                case offset:
                    return new SnortOffsetOption(value);
                default:
                    return new NotClassedSnortOption(type, value);
            }
        } catch (RuntimeException e) {
            throw new Exception("Could not parse option from " + option, e);
        }
    }

    @Override
    public String toString() {
        return "SnortOption{" +
                "type=" + type +
                ", value='" + value + '\'' +
                '}';
    }

    public abstract boolean match(PacketInfo packetInfo) throws Exception;

    public abstract void finalize(PeakableIterator<SnortOption> iter) throws Exception;
}
