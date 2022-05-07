package side.snort.port;

public class SnortPortRange extends SnortPort {
    private final int start;
    private final int end;
    private final boolean isNot;

    public SnortPortRange(int start, int end, boolean isNot) {
        super();
        this.start = start;
        this.end = end;
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortPortRange{" +
                "start=" + start +
                ", end=" + end +
                ", isNot=" + isNot +
                '}';
    }


    @Override
    public boolean matches(int packetPort) {
        boolean matches = packetPort >= start && packetPort <= end;
        if (isNot) {
            return !matches;
        }
        return matches;
    }
}
