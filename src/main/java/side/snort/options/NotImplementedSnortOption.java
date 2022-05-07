package side.snort.options;

import side.PacketInfo;
import side.utils.PeakableIterator;

public class NotImplementedSnortOption extends SnortOption {
    protected NotImplementedSnortOption(SnortOptionType type, String value) {
        super(type, value);
    }

    @Override
    public final boolean match(PacketInfo packetInfo) {
        logger.warn("Not implemented {}", this);
        return true;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }

    @Override
    public String toString() {
        return "{" +
                "type=" + type +
                ", value='" + value + '\'' +
                '}';
    }
}
