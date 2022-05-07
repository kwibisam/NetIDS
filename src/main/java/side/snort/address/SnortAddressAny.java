package side.snort.address;

import com.km.ids.analyser.snort.address.*;
import java.net.InetAddress;

public class SnortAddressAny extends SnortAddress {
    private boolean isNot;

    public SnortAddressAny(boolean isNot) {
        this.isNot = isNot;
    }

    @Override
    public String toString() {
        return "SnortAddressAny{" +
                "isNot=" + isNot +
                '}';
    }

    @Override
    public boolean matches(InetAddress packetAddr) {
        return !isNot;
    }
}
