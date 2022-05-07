package side.snort.port;


import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class SnortPort {
    public static SnortPort of(String value) throws Exception {
        String s = value;
        boolean isNot = false;
        if (s.startsWith("!")) {
            isNot = true;
            s = s.substring(1);
        }

        if ("any".equals(s)) {
            return new SnortPortAny(isNot);
        }

        s = s.replaceAll("\\$FILE_DATA_PORTS", "123");
        s = s.replaceAll("\\$HTTP_PORTS", "234");
        s = s.replaceAll("\\$HTTPS_PORTS", "345");
        s = s.replaceAll("\\$FTP_PORTS", "3,4,5");
        s = s.replaceAll("\\$ORACLE_PORTS", "6,7,8");

        Pattern p = Pattern.compile("\\[(.*)\\]");
        Matcher m = p.matcher(s);
        if (m.matches()) {
            s = m.group(1);
        }

        String[] chunks = s.split(",");
        List<SnortPort> out = new LinkedList<>();
        for (String chunk : chunks) {
            out.add(compute(chunk, isNot));
        }

        if (out.isEmpty()) {
            return new SnortPortAny(isNot);
        }
        if (out.size() == 1) {
            return out.get(0);
        }
        return new SnortPortComplex(out);
    }

    private static SnortPort compute(String chunk, boolean isNot) throws Exception {
        String s = chunk;

        if (s.matches("^\\d+:\\d+$")) {
            String[] parts = s.split(":");
            try {
                int start = Integer.parseInt(parts[0]);
                int end = Integer.parseInt(parts[1]);
                return new SnortPortRange(start, end, isNot);
            } catch (NumberFormatException e) {
                throw new Exception("Could not get port number from " + s + " in " + chunk);
            }
        }
        if (s.matches("^\\d+$")) {
            try {
                int port = Integer.parseInt(s);
                return new SnortPortSingle(port, isNot);
            } catch (NumberFormatException e) {
                // Do nothing
            }
        }
        if (s.matches("^\\d+:$")) {
            try {
                int port = Integer.parseInt(s.substring(0, s.length() - 1));
                return new SnortPortRange(port, 65536, isNot);
            } catch (NumberFormatException e) {
                // Do nothing
            }
        }
        if (s.matches("^:\\d+$")) {
            try {
                int port = Integer.parseInt(s.substring(1));
                return new SnortPortRange(0, port, isNot);
            } catch (NumberFormatException e) {
                // Do nothing
            }
        }

        if (s.contains(":")) {
            String[] parts = s.split(":");
            try {
                int start = -1;
                if (parts[0].trim().length() > 0) {
                    start = Integer.parseInt(parts[0]);
                }
                int end = -1;
                if (parts.length > 1 && parts[1].trim().length() > 0) {
                    end = Integer.parseInt(parts[1]);
                }
                return new SnortPortRange(start, end, isNot);
            } catch (NumberFormatException e) {
                throw new Exception("Could not get port number from " + s + " in " + chunk);
            }
        }

        if (s.matches("^\\d+(,\\d+)+$")) {
            String[] parts = s.split(",");
            try {
                List<Integer> ports = new ArrayList<>(parts.length);
                for (String part : parts) {
                    ports.add(Integer.valueOf(part));
                }
                return new SnortPortList(ports, isNot);
            } catch (NumberFormatException e) {
                throw new Exception("Could not get port number from " + s + " in " + chunk);
            }
        }

        try {
            int port = Integer.parseInt(s);
            return new SnortPortSingle(port, isNot);
        } catch (NumberFormatException e) {
            // Do nothing
        }

        if (s.contains("<") || s.contains(">")) {
            return new SnortPortMinMax(s);
        }

        throw new Exception("Unknown port syntax " + chunk);
    }

    public abstract boolean matches(int packetPort);
}
