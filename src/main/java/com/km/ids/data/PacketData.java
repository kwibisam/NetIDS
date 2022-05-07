package com.km.ids.data;

import com.km.ids.analyser.snort.SnortProtocol;
import java.net.InetAddress;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpPacket.IpHeader;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Packet.Header;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.TransportPacket.TransportHeader;

/**
 *
 * @author Kwibisa Mwene
 */
public class PacketData {
    private Packet packet;
    public PacketData(Packet packet){
        this.packet = packet;
    }
    
    public SnortProtocol getProtocol(){
        
        return SnortProtocol.from(ipHeader().getProtocol().name().toLowerCase());
    }
    public InetAddress getSrcIp(){
        return ipHeader().getSrcAddr();
    }
    
    public InetAddress getDstIp(){
        return ipHeader().getDstAddr();
    }
    
    public int getSrcPort(){
        return transpHeader().getSrcPort().value();
    }
    
     public int getDstPort(){
        return transpHeader().getSrcPort().value();
    }
    //get IP Header
    private IpHeader ipHeader(){
        return packet.get(IpPacket.class).getHeader();
    }
    
    //get Transport Header
    private TransportHeader transpHeader(){
        return packet.get(TransportPacket.class).getHeader();
    }
    
    //get Dns Header
    private Header getDnsHeader(){
        return packet.get(DnsPacket.class).getHeader();
    }
    
    //ARP packet
    private Header getArp(){
        return packet.get(ArpPacket.class).getHeader();
    }
    
}
