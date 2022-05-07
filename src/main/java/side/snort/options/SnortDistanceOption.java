package side.snort.options;


public class SnortDistanceOption extends SwallowedSnortOption {
    private final int distance;

    public SnortDistanceOption(String value) throws Exception {
        super(SnortOptionType.distance, value);
        this.distance = parseDistance(value);
    }

    private static int parseDistance(String value) throws Exception {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new Exception("Illegal distance " + value, e);
        }
    }

    public int getDistance() {
        return distance;
    }
}
