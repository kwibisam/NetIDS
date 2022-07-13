package com.kwibisa.ids.analyser;

import org.pcap4j.packet.Packet;
import java.net.InetAddress;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TransportPacket;

public class PacketInfo {
    private final Packet packet;

    public PacketInfo(Packet packet) {
        this.packet = packet;
    }

    public Packet getPacket() {
        return packet;
    }

    public RuleProtocol protocol() {
        String p = packet.get(IpPacket.class).getHeader().getProtocol().name();
        p = p.toLowerCase();
        return RuleProtocol.from(p);
    }

    public byte[] payload() {
        return packet.getPayload().getRawData();
    }

    public InetAddress getSrcAddr(){
        return packet.get(IpPacket.class).getHeader().getSrcAddr();
    }

    public int getSrcPort() {
        if(packet.get(TransportPacket.class) == null){
            return -1;
        }
        return packet.get(TransportPacket.class).getHeader().getSrcPort().value();
    }

    public InetAddress getDstAddr() {
        return packet.get(IpPacket.class).getHeader().getDstAddr();
    }

    public int getDstPort(){
         if(packet.get(TransportPacket.class) == null){
            return -1;
        }
        return packet.get(TransportPacket.class).getHeader().getDstPort().value();
    }
    
    public String getService(){
        if(getDstPort() >= 49152 && getDstPort() <= 65535){
            return "private";
        }
       
        switch(getDstPort()){
            case 5190:
                return "aol";
            case 113:
                return "auth";
            case 179:
                return "bgp";
            case 105:
                return"csnet_ns";
            case 84:
                return "ctf";
            case 13:
                return "daytime";
            case 9:
                return "discard";
            case 53:
                return "domain";
            case 7:
                return "echo";
            case 21:
                return "ftp";
            case 80:
                return "http";
            case 22:
                return "ssh";
            case 23:
                return "telnet";
            case 2784:
                return "http_2784";
            case 443:
                return "http_443";
            case 8001:
                return "http_8001";
            case 993:
                return "imap4";
            case 137:
                return "netbios_ns";
            case 139:
                return "netbios_ssn";
            case 25:
                return "smtp";
            case 110:
                return "pop_3";
        }
        return "other";
    }
    
    public Connection getConnectionInfo(){
        return new Connection(getSrcAddr(),getSrcPort(), getDstAddr(),getDstPort());
    }
      
    
     @Override
    public String toString() {
        return "PacketInfo{" +
                "packet=" + packet +
                '}';
    }
}
