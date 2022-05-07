package side.snort.options;


public class SnortDepthOption extends SwallowedSnortOption {
    private final int depth;

    public SnortDepthOption(String value) throws Exception {
        super(SnortOptionType.depth, value);
        this.depth = parseDepth(value);
    }

    private static int parseDepth(String value) throws Exception {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new Exception("Illegal depth " + value, e);
        }
    }

    public int getDepth() {
        return depth;
    }
}
