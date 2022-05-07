package side.snort.options;


public class SnortWithinOption extends SwallowedSnortOption {
    private final int within;

    public SnortWithinOption(String value) throws Exception {
        super(SnortOptionType.within, value);
        this.within = parseWithin(value);
    }

    private static int parseWithin(String value) throws Exception {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new Exception("Illegal distance " + value, e);
        }
    }

    public int getWithin() {
        return within;
    }
}
