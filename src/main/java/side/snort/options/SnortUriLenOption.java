package side.snort.options;

import side.PacketInfo;
import side.snort.ParserUtils;
import side.utils.PeakableIterator;
import org.pcap4j.packet.TransportPacket;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import static side.snort.ParserUtils.minMaxParser;


public class SnortUriLenOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;
    private boolean normalized = false;

    public SnortUriLenOption(String value) throws Exception {
        super(SnortOptionType.urilen, value);

        String v = value;
        if (value.contains(",")) {
            String[] parts = v.split(",");
            if (parts.length != 2) {
                throw new Exception("Too many commas in " + value);
            }
            v = parts[0];
            if ("norm".equalsIgnoreCase(parts[1])) {
                normalized = true;
            } else {
                throw new Exception("Unknown type " + parts[1]);
            }
        }

        minMax = minMaxParser(v);
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws Exception {
        return tryMatch(packetInfo.fetchPacket(TransportPacket.class));
    }

    private boolean tryMatch(TransportPacket packet) throws Exception {
        if (packet != null) {
            if (packet.getPayload() == null) {
                return false;
            }
            byte[] rawData = packet.getPayload().getRawData();
            CharsetDecoder decoder = StandardCharsets.US_ASCII.newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPLACE);
            decoder.onMalformedInput(CodingErrorAction.IGNORE);
            try {
                CharBuffer chars = decoder.decode(ByteBuffer.wrap(rawData));
                System.out.println("###################");
                System.out.println(packet.getClass().getSimpleName());
                System.out.println(chars.toString());
                System.out.println("###################");
            } catch (CharacterCodingException e) {
                throw new Exception("Could not read char", e);
            }
        }
        return false;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
