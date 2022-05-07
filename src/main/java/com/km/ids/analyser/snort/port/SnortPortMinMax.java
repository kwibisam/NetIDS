package com.km.ids.analyser.snort.port;

import com.km.ids.analyser.snort.ParserUtils;
import static com.km.ids.analyser.snort.ParserUtils.minMaxParser;



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
