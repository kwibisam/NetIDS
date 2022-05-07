package side.snort.options;

import side.PacketInfo;
import side.snort.ParserUtils;
import side.utils.PeakableIterator;

import static side.snort.ParserUtils.minMaxParser;


public class SnortDSizeOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;

    public SnortDSizeOption(String value) throws Exception {
        super(SnortOptionType.dsize, value);

        minMax = minMaxParser(value);
    }

    @Override
    public boolean match(PacketInfo packetInfo) {
        return minMax.match(packetInfo.payload().length);
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
