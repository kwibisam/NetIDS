package side.snort.options;

public class NotClassedSnortOption extends NotImplementedSnortOption {
    public NotClassedSnortOption(SnortOptionType type, String value) {
        super(type, value);
//        logger.warn("Snort option without class: {}", this);
    }
}
