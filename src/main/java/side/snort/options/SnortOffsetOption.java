package side.snort.options;


public class SnortOffsetOption extends SwallowedSnortOption {
    private final int offset;

    public SnortOffsetOption(String value) throws Exception {
        super(SnortOptionType.offset, value);
        this.offset = parseOffset(value);
    }

    private static int parseOffset(String value) throws Exception {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new Exception("Illegal offset " + value, e);
        }
    }

    public int getOffset() {
        return offset;
    }
}
