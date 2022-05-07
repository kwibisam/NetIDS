package side.snort.options;

import side.PacketInfo;
import side.utils.PeakableIterator;

import java.nio.charset.StandardCharsets;
import java.util.*;


public class SnortContentOption extends SnortOption {
    private boolean caseSensitive = true;
    private int distance = 0;
    private int within = 0;
    private int depth = 0;
    private int offset = 0;

    private List<Byte> lower = new LinkedList<>();
    private List<Byte> higher = null;


    public SnortContentOption(String value) {
        super(SnortOptionType.content, value);
    }

    @Override
    public boolean match(PacketInfo packetInfo) {
        byte[] data = packetInfo.payload();

        // Compute start of check
        int start = packetInfo.getPointerPos();
        if (offset != 0) {
            start = offset;
        }
        if (distance != 0) {
            start += distance;
        }

        // Compute end of check
        int end = data.length;
        if (depth != 0) {
            end = Math.min(start + depth, end);
        }
        if (within != 0) {
            end = Math.min(start + within, end);
        }

        if (start >= end) {
            // Not enough data to check
            return false;
        }

        if (start + lower.size() > data.length) {
            // Not enough data to fit
            return false;
        }

        byte firstLower = lower.get(0);
        byte firstHigher = firstLower;
        if (higher != null) {
            firstHigher = higher.get(0);
        }
        for (int i = start; i <= end - lower.size(); i++) {
            byte current = data[i];
            if (current == firstLower || current == firstHigher) {
                if (subMatching(data, i)) {
                    packetInfo.setPointerPos(i + lower.size());
                    return true;
                }
            }
        }

        return false;
    }

    private boolean subMatching(byte[] data, int startPos) {
        for (int i = 0; i < lower.size(); i++) {
            byte current = data[startPos + i];
            if (current != lower.get(i)) {
                if (higher == null || current != higher.get(i)) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) throws Exception {
        configure(iter);

        lower = new LinkedList<>();
        higher = null;

        if (!caseSensitive) {
            higher = new LinkedList<>();
        }

        boolean hexa = false;
        String hexaFirst = null;

        for (char c : value.toCharArray()) {
            if (c == '|') {
                hexa = !hexa;
            } else if (c == ' ' && hexa) {
                // skip
            } else {
                if (!hexa) {
                    String varA = String.valueOf(c);

                    if (higher != null) {
                        lower.addAll(byteOf(varA.toLowerCase(Locale.ENGLISH)));
                        higher.addAll(byteOf(varA.toUpperCase(Locale.ENGLISH)));
                    } else {
                        lower.addAll(byteOf(varA));
                    }
                } else {
                    if (hexaFirst == null) {
                        hexaFirst = String.valueOf(c);
                    } else {
                        String pair = hexaFirst + c;
                        hexaFirst = null;
                        try {
                            int parsed = Integer.parseInt(pair, 16);
                            lower.add((byte) parsed);
                            if (higher != null) {
                                higher.add((byte) parsed);
                            }
                        } catch (NumberFormatException e) {
                            throw new Exception("Could not parse hexa from " + pair + " as part of value " + value, e);
                        }
                    }
                }
            }
        }
    }

    private List<Byte> byteOf(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 1) {
            return Collections.singletonList(bytes[0]);
        }
        List<Byte> out = new ArrayList<>(bytes.length);
        for (byte b : bytes) {
            out.add(b);
        }
        return out;
    }

    private void configure(PeakableIterator<SnortOption> iter) {
        while (iter.hasNext()) {
            SnortOption candidate = iter.peak();
            switch (candidate.type) {
                case nocase:
                    iter.swallow();
                    iter.remove();
                    this.caseSensitive = false;
                    break;
                case distance:
                    SnortDistanceOption distanceOption = (SnortDistanceOption) iter.next();
                    iter.remove();
                    this.distance = distanceOption.getDistance();
                    break;
                case within:
                    SnortWithinOption withinOption = (SnortWithinOption) iter.next();
                    iter.remove();
                    this.within = withinOption.getWithin();
                    break;
                case depth:
                    SnortDepthOption depthOption = (SnortDepthOption) iter.next();
                    iter.remove();
                    this.depth = depthOption.getDepth();
                    break;
                case offset:
                    SnortOffsetOption offsetOption = (SnortOffsetOption) iter.next();
                    iter.remove();
                    this.offset = offsetOption.getOffset();
                    break;
                case fast_pattern:
                    iter.swallow();
                    iter.remove();
                    break;
                default:
                    return;
            }
        }
    }
}
