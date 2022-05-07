package side.snort.address;

import com.km.ids.analyser.snort.address.*;
import org.apache.commons.net.util.SubnetUtils;

import java.net.InetAddress;

public class SnortAddressNetwork extends SnortAddress {

    private final String ip;
    private final int mask;
    private final boolean isNot;
    private final SubnetUtils.SubnetInfo subnet;

    public SnortAddressNetwork(String ip, int mask, boolean isNot) {
        super();
        this.ip = ip;
        this.mask = mask;
        this.isNot = isNot;
        this.subnet = new SubnetUtils(ip + "/" + mask).getInfo();
    }

    @Override
    public String toString() {
        return "SnortAddressNetwork{" +
                "ip='" + ip + '\'' +
                ", mask='" + mask + '\'' +
                ", isNot=" + isNot +
                '}';
    }

    @Override
    public boolean matches(InetAddress packetAddress) throws Exception {
        if (packetAddress == null) {
            return false;
        }

        String ip = packetAddress.getHostAddress();
        if (!ip.contains(".")) {
            // IPv6
            return false;
        }
        try {
            boolean matches = subnet.isInRange(ip);
            if (isNot) {
                return !matches;
            }
            return matches;
        } catch (IllegalArgumentException e) {
            throw new Exception("Could not parse IP address " + ip, e);
        }
    }
}
