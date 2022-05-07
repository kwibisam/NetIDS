package com.km.ids;


import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;

/**
 *
 * @author Kwibisa Mwene
 */
public class Rule {
    
    private String action;
    private String protocol;
    private String srcAddr;
    private String srcPort;
    private String dir;
    private String dstAddr;
    private String dstPort;

    public Rule(String action, String protocol, String srcAddr, String srcPort, String dir, String dstAddr, String dstPort) {
        this.action = action;
        this.protocol = protocol;
        this.srcAddr = srcAddr;
        this.srcPort = srcPort;
        this.dir = dir;
        this.dstAddr = dstAddr;
        this.dstPort = dstPort;
    }

    
    public boolean match(Packet packet){
        
        //match source address
        if(!matchSrcAddr(packet.get(IpPacket.class).getHeader().getSrcAddr().getHostAddress())){
            return false;
        }
        
        //matchc source port
        if(!srcPort.equals("any") && srcPort.equals(packet.get(TransportPacket.class).getHeader().getSrcPort().valueAsString())){
            return false;
        }
        
        //match direction 
        
        switch(dir){
            case "<>": //match all
                break;
            case "->":
                if(!isInternal(packet.get(IpPacket.class).getHeader().getSrcAddr())){
                    return false;
                }
                break;
            case "<-":
                if(isInternal(packet.get(IpPacket.class).getHeader().getSrcAddr())){
                    return false;
                }
        }
        
         //match dst address
        if(!matchDstAddr(packet.get(IpPacket.class).getHeader().getDstAddr().getHostAddress())){
            return false;
        }
        
        //matchc dst port
        if(!srcPort.equals("any") && srcPort.equals(packet.get(TransportPacket.class).getHeader().getDstPort().valueAsString())){
            return false;
        }
        return true;
    }
    
    private boolean matchSrcAddr(String addr){
        
        if(srcAddr.equals("any")){
            return true;
        }
        return srcAddr.equals(addr);
    }
    
    private boolean matchDstAddr(String addr){
        
        if(dstAddr.equals("any")){
            return true;
        }
        return dstAddr.equals(addr);
    }
    
    private boolean isInternal(InetAddress srcAddr){
        try {
            Iterator<NetworkInterface> iter = NetworkInterface.getNetworkInterfaces().asIterator();
            while(iter.hasNext()){
                NetworkInterface nif = iter.next();
                Iterator<InetAddress> iter2 = nif.getInetAddresses().asIterator();
                while(iter2.hasNext()){
                    InetAddress addr = iter2.next();
                    if (addr.getHostAddress().equals(srcAddr.getHostAddress())) {
                        return true;
                    }
                }
            }
        } 
        catch (SocketException ex) {
            Logger.getLogger(Rule.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return false;
    }
    public String getAction() {
        return action;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getSrcAddr() {
        return srcAddr;
    }

    public String getSrcPort() {
        return srcPort;
    }

    public String getDstAddr() {
        return dstAddr;
    }

    public String getDstPort() {
        return dstPort;
    }  
}
