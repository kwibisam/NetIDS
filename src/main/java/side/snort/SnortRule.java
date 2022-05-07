package side.snort;

import side.PacketInfo;
import side.snort.options.SnortOption;
import side.utils.PeakableIterator;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class SnortRule {
    private final SnortAction action;
    private final SnortProtocol protocol;
    private final SnortIp source;
    private final String direction;
    private final SnortIp destination;
    private final String rawText;
    private List<SnortOption> options = Collections.emptyList();
    private String sid;
    private String msg;
    private String rev;
    private String classType;
    private String metadata;
    private String reference;

    public SnortRule(String rawText,
                     SnortAction action,
                     SnortProtocol protocol,
                     SnortIp source,
                     String direction,
                     SnortIp destination) {
        this.rawText = rawText;
        this.action = action;
        this.protocol = protocol;
        this.source = source;
        this.direction = direction;
        this.destination = destination;
    }

    public void setOptions(List<SnortOption> options) {
        this.options = options;
    }

    @Override
    public String toString() {
        return "SnortRule{" +
                "action=" + action +
                ", protocol=" + protocol +
                ", source=" + source +
                ", direction='" + direction + '\'' +
                ", destination=" + destination +
                ", options=" + options +
                '}';
    }

    public boolean match(PacketInfo packetInfo) throws Exception {
        try {
            if (!source.matches(packetInfo.getSrcAddr(), packetInfo.getSrcPort())) {
                return false;
            }
            if (!destination.matches(packetInfo.getDstAddr(), packetInfo.getDstPort())) {
                return false;
            }
            switch (direction) {
                case "<>":
                    // Match all
                    break;
                case "->":
                    if (!isInternal(packetInfo.getSrcAddr()) || isInternal(packetInfo.getDstAddr())) {
                        return false;
                    }
                    break;
                case "<-":
                    if (isInternal(packetInfo.getSrcAddr()) || !isInternal(packetInfo.getDstAddr())) {
                        return false;
                    }
                    break;
            }
        } catch (Exception e) {
            throw new Exception("Engine executed an unsupported operation", e);
        }

        PeakableIterator<SnortOption> iter = new PeakableIterator<>(options.iterator());
        while (iter.hasNext()) {
            try {
                if (!iter.next().match(packetInfo)) {
                    return false;
                }
            } catch (Exception e) {
                System.err.println("Could not match rule");
                e.printStackTrace();
            }
        }

        return true;
    }

    private boolean isInternal(InetAddress srcAddr) throws Exception {
        try {
            Iterator<NetworkInterface> iter = NetworkInterface.getNetworkInterfaces().asIterator();
            while (iter.hasNext()) {
                NetworkInterface iface = iter.next();
                Iterator<InetAddress> iter2 = iface.getInetAddresses().asIterator();
                while (iter2.hasNext()) {
                    InetAddress addr = iter2.next();
                    if (addr.getHostAddress().equals(srcAddr.getHostAddress())) {
                        return true;
                    }
                }
            }
            return false;
        } catch (SocketException e) {
            throw new Exception("Could not list interfaces", e);
        }
    }

    public void setSid(String sid) {
        this.sid = sid;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public void setRev(String rev) {
        this.rev = rev;
    }

    public void setClassType(String classType) {
        this.classType = classType;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }
}
