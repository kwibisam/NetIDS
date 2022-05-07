package side.snort.port;

import side.snort.ParserUtils;
import static side.snort.ParserUtils.minMaxParser;

public class SnortPortMinMax extends SnortPort {
    private final ParserUtils.MinMaxValue minMax;

    public SnortPortMinMax(String s) throws Exception {
        super();
        minMax = minMaxParser(s);
    }

    @Override
    public boolean matches(int packetPort) {
        return minMax.match(packetPort);
    }
}
