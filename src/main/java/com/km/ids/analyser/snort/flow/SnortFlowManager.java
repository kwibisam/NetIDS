package com.km.ids.analyser.snort.flow;


import com.km.ids.analyser.snort.SnortProtocol;
import com.km.ids.analyser.utils.Connection;
import com.km.ids.data.PacketInfo;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;
import java.util.*;

public class SnortFlowManager {
    private final Map<Connection, SnortFlow> stateMap = new LinkedHashMap<>();
    private final Map<Connection, List<TcpPacket>> tcpToServer = new LinkedHashMap<>();
    private final Map<Connection, List<TcpPacket>> tcpFromServer = new LinkedHashMap<>();
    private final Map<Connection, Map<String, Boolean>> flowbits = new LinkedHashMap<>();
    private final Map<Connection, InetAddress> serverIdentity = new LinkedHashMap<>();

    public void handle(PacketInfo packetInfo) throws Exception {
        try {
            Connection connection = packetInfo.connectionInfo();

            InetAddress identity = serverIdentity.getOrDefault(connection, null);
            packetInfo.setServer(identity);
            SnortFlow currentFlow = stateMap.getOrDefault(connection, SnortFlow.UNKNOWN);
            packetInfo.setFlow(currentFlow);
            packetInfo.setFlowManager(this);

            if (packetInfo.protocol() == SnortProtocol.tcp) {
                handleTcpPacket(currentFlow, connection, packetInfo);
            }
            stateMap.put(connection, packetInfo.getFlow());
            packetInfo.setFlowbits(flowbits.get(connection));
        } catch (Exception e) {
            throw new Exception("Could not handle packet", e);
        }
    }

    private void handleTcpPacket(SnortFlow currentFlow, Connection connection, PacketInfo packetInfo) throws Exception {
        TcpPacket packet = packetInfo.getPacket().get(TcpPacket.class);
        if (packet == null) {
            return;
        }

        List<TcpPacket> packets;
        try {
            if (isFromServer(packetInfo)) {
                if (!tcpFromServer.containsKey(connection)) {
                    tcpFromServer.put(connection, new LinkedList<>());
                }
                packets = tcpFromServer.get(connection);
            } else {
                if (!tcpToServer.containsKey(connection)) {
                    tcpToServer.put(connection, new LinkedList<>());
                }
                packets = tcpToServer.get(connection);
            }
            if (packet.getPayload() != null && packet.getPayload().length() > 0) {
                packets.add(packet);
            }

            TcpPacket.TcpHeader tcpHeader = packet.getHeader();
            if (tcpHeader.getSyn() && !tcpHeader.getAck()) {
                packetInfo.setFlow(SnortFlow.SYN_RECEIVED);
                serverIdentity.put(connection, packetInfo.getDstAddr());
                flowbits.put(connection, new HashMap<>());
            } else if (tcpHeader.getSyn()) {
                packetInfo.setFlow(SnortFlow.SYN_ACKED);
                serverIdentity.put(connection, packetInfo.getSrcAddr());
                if (!flowbits.containsKey(connection)) {
                    flowbits.put(connection, new HashMap<>());
                }
            } else if ((currentFlow == SnortFlow.SYN_ACKED || currentFlow == SnortFlow.SYN_RECEIVED) && tcpHeader.getAck()) {
                packetInfo.setFlow(SnortFlow.ESTABLISHED);
                serverIdentity.put(connection, packetInfo.getDstAddr());
                if (!flowbits.containsKey(connection)) {
                    flowbits.put(connection, new HashMap<>());
                }
            } else if (tcpHeader.getFin()) {
                packetInfo.setFlow(SnortFlow.FINISHED);
                flowbits.remove(connection);

                rebuildPackets(tcpFromServer.remove(connection));
                rebuildPackets(tcpToServer.remove(connection));
            }
        } catch (Exception e) {
            throw new Exception("Could not track TCP packet", e);
        }
    }

    private void rebuildPackets(List<TcpPacket> tcpPackets) {
        if (tcpPackets == null || tcpPackets.isEmpty()) {
            return;
        }

        Long minSeqId = null;
        Long maxSeqId = null;
        for (TcpPacket packet : tcpPackets) {
            if (minSeqId == null) {
                minSeqId = packet.getHeader().getSequenceNumberAsLong();
            }
            if (maxSeqId == null) {
                maxSeqId = packet.getHeader().getSequenceNumberAsLong();
            }
            minSeqId = Math.min(minSeqId, packet.getHeader().getSequenceNumberAsLong());
            maxSeqId = Math.max(maxSeqId, packet.getHeader().getSequenceNumberAsLong());
        }
    }

    @Override
    public String toString() {
        return "SnortFlowManager{" +
                "stateMap=" + stateMap +
                '}';
    }

    public boolean isEstablished(PacketInfo packetInfo) throws Exception {
        Connection connection = packetInfo.connectionInfo();
        return stateMap.getOrDefault(connection, SnortFlow.UNKNOWN).equals(SnortFlow.ESTABLISHED);
    }

    public boolean isFromServer(PacketInfo packetInfo) throws Exception {
        Connection connection = packetInfo.connectionInfo();
        return packetInfo.getSrcAddr().equals(serverIdentity.getOrDefault(connection, null));
    }
}
