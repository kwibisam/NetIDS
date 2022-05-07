package com.km.ids.analyser.utils;

import com.km.ids.analyser.snort.SnortRule;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.km.ids.data.PacketInfo;
import java.util.LinkedList;

/**
 *
 * @author Kwibisa Mwene
 */
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

