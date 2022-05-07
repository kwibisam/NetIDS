package com.km.ids.data;


import com.km.ids.analyser.snort.SnortProtocol;
import com.km.ids.analyser.snort.flow.SnortFlow;
import com.km.ids.analyser.snort.flow.SnortFlowManager;
import com.km.ids.analyser.utils.Connection;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.Map;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TransportPacket;

public class PacketInfo {
    private final Packet packet;

    private int pointerPos = 0;
    private SnortFlowManager flowManager;
    private SnortFlow flow;
    private InetAddress server;
    private Map<String, Boolean> flowbits;

    public PacketInfo(Packet packet) {
        this.packet = packet;
    }

    public Packet getPacket() {
        return packet;
    }

    public SnortProtocol protocol() {
        String p = packet.get(IpPacket.class).getHeader().getProtocol().name();
        p = p.toLowerCase();
        return SnortProtocol.from(p);
    }

    public byte[] payload() {
        return packet.getPayload().getRawData();
    }

    public int getPointerPos() {
        return pointerPos;
    }

    public void setPointerPos(int pointerPos) {
        this.pointerPos = pointerPos;
    }

    public InetAddress getSrcAddr() throws Exception {
        return packet.get(IpPacket.class).getHeader().getSrcAddr();
    }

    public int getSrcPort() throws Exception {
        return packet.get(TransportPacket.class).getHeader().getSrcPort().value();
    }

    public InetAddress getDstAddr() throws Exception {
        return packet.get(IpPacket.class).getHeader().getDstAddr();
    }

    public int getDstPort() throws Exception {
        return packet.get(TransportPacket.class).getHeader().getDstPort().value();
    }

    public SnortFlowManager getFlowManager() {
        return flowManager;
    }

    public void setFlowManager(SnortFlowManager flowManager) {
        this.flowManager = flowManager;
    }

    public void setFlow(SnortFlow flow) {
        this.flow = flow;
    }

    public SnortFlow getFlow() {
        return flow;
    }

    public void setServer(InetAddress server) {
        this.server = server;
    }

    public InetAddress getServer() {
        return server;
    }

    public <T extends Packet> T fetchPacket(Class<T> clazz) {
        return fetchThisOrPacket(clazz, packet);
    }

    @SuppressWarnings("unchecked")
    private <T extends Packet> T fetchThisOrPacket(Class<T> clazz, Packet p) {
        if (p == null) {
            return null;
        }
        if (clazz.isInstance(p)) {
            return (T) p;
        }
        return fetchThisOrPacket(clazz, p.getPayload());
    }

    public void setFlowbits(Map<String, Boolean> flowbits) {
        this.flowbits = flowbits;
    }

    public void putFlowbit(String variable) {
        this.flowbits.put(variable, true);
    }

    public boolean readFlowbit(String variable) {
        Boolean b = this.flowbits.get(variable);
        if (b == null) {
            return false;
        }
        return b;
    }

    public void dropFlowbit(String variable) {
        this.flowbits.remove(variable);
    }

    public Connection connectionInfo() throws Exception {
        return new Connection(getSrcAddr(), getSrcPort(), getDstAddr(), getDstPort());
    }

    public int getIcmpType() throws Exception {
        return 0;
    }

    @Override
    public String toString() {
        return "PacketInfo{" +
                "packet=" + packet +
                ", flow=" + flow +
                ", server=" + server +
                ", flowbits=" + flowbits +
                '}';
    }
}
