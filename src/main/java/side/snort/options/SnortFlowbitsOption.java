package side.snort.options;

import side.PacketInfo;
import side.utils.PeakableIterator;


public class SnortFlowbitsOption extends SnortOption {
    private final FlowbitAction action;
    private final String variable;

    public SnortFlowbitsOption(String value) throws Exception {
        super(SnortOptionType.flowbits, value);

        String[] parts = value.split(",");
        try {
            action = FlowbitAction.valueOf(parts[0]);
        } catch (IllegalArgumentException e) {
            throw new Exception("Unknown flowbit type for " + value, e);
        }
        if (parts.length > 1) {
            variable = parts[1];
        } else {
            variable = null;
        }
        if (parts.length > 2) {
            throw new Exception("Unsupport flowbit format " + value);
        }

        if (action != FlowbitAction.noalert && variable == null) {
            throw new Exception("Missing variable for " + value);
        }
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws Exception {
        switch (action) {
            case set:
                packetInfo.putFlowbit(variable);
                return true;
            case isset:
                return packetInfo.readFlowbit(variable);
            case unset:
                packetInfo.dropFlowbit(variable);
                return true;
            case toggle:
                if (packetInfo.readFlowbit(variable)) {
                    packetInfo.dropFlowbit(variable);
                } else {
                    packetInfo.putFlowbit(variable);
                }
                return true;
            case noalert:
                throw new Exception("Alerting is not implemented");
            case isnotset:
                return !packetInfo.readFlowbit(variable);
        }
        throw new Exception("Unknown flowbit action " + action);
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
