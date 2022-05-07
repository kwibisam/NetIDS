package side.snort.options;

/**
 * @author clerc
 * @since 2020/04/13
 */
public class DataPosition {
    private final DataPositionType type;
    private final Long offest;
    private final SnortPositionType positioning;

    public DataPosition(DataPositionType type,
                        Long offest,
                        SnortPositionType positioning) {
        this.type = type;
        this.offest = offest;
        this.positioning = positioning;
    }

    public DataPositionType getType() {
        return type;
    }

    public Long getOffest() {
        return offest;
    }

    public SnortPositionType getPositioning() {
        return positioning;
    }
}
