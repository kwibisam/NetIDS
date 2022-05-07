package side.snort.options;

import side.PacketInfo;
import side.utils.PeakableIterator;


public class SnortFlowOption extends SnortOption {
    private boolean established = false;
    private boolean toServer = false;
    private boolean fromServer = false;

    public SnortFlowOption(String value) {
        super(SnortOptionType.flow, value);
        parseValue(value);
    }

    private void parseValue(String value) {
        String[] parts = value.split(",");
        for (String part : parts) {
            if (part.equalsIgnoreCase("established")) {
                established = true;
            } else if (part.equalsIgnoreCase("to_server")) {
                toServer = true;
            } else if (part.equalsIgnoreCase("from_server")) {
                fromServer = true;
            }
        }
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws Exception {
        try {
            if (established && !packetInfo.getFlowManager().isEstablished(packetInfo)) {
                return false;
            }
            if (fromServer && !packetInfo.getFlowManager().isFromServer(packetInfo)) {
                return false;
            }
            if (toServer && packetInfo.getFlowManager().isFromServer(packetInfo)) {
                return false;
            }
        } catch (Exception e) {
            throw new Exception("Could not check flow of packet", e);
        }
        return true;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        //Nothing to do
    }
}
