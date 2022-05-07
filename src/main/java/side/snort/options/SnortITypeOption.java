package side.snort.options;

import side.PacketInfo;
import side.snort.ParserUtils;
import side.snort.SnortProtocol;
import side.utils.PeakableIterator;

import static side.snort.ParserUtils.minMaxParser;


public class SnortITypeOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;

    protected SnortITypeOption(String value) throws Exception {
        super(SnortOptionType.itype, value);

        minMax = minMaxParser(value);
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws Exception {
        if (packetInfo.protocol() != SnortProtocol.icmpv4) {
            return false;
        }
        try {
            return minMax.match(packetInfo.getIcmpType());
        } catch (Exception e) {
            throw new Exception("Error matching ICMP type", e);
        }
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
