package com.km.ids.data;


import com.km.ids.Main;
import com.km.ids.analyser.snort.SnortMatcher;
import com.km.ids.analyser.snort.SnortRule;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author Kwibisa Mwene
 */
public class PcapMonitor extends Thread implements PacketListener {
    
    private List<Packet> packets = new ArrayList<>();
    private PcapNetworkInterface nif;
    private PcapHandle handle;
    
    private static final int SNAPLEN = 65534;
    private static final int READ_TIMEOUT = 10;
    private static final int PACKET_COUNT = 10;
    private static final int INFINITE = -1;
    private static final String FILTER = "";
    private Main ui;
    private SnortMatcher snort;
    
   
    public static int tcpCount = 0;
    public static int udpCount = 0;
    public static int icmpCnt = 0;
    
    public PcapMonitor(PcapNetworkInterface nif, Main ui, SnortMatcher snort){
        this.snort = snort;
        this.ui = ui;
        this.nif = nif;
        initNif(nif);
    }
    
    private PcapHandle initNif(PcapNetworkInterface nif){
        try {
            handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            handle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);      
        } 
        catch (PcapNativeException | NotOpenException ex) {
            Logger.getLogger(PcapMonitor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return handle;
    }
    
    public void loop(){
        try {
            handle.loop(INFINITE, this);
        } 
        catch (PcapNativeException | InterruptedException | NotOpenException ex) {
            Logger.getLogger(PcapMonitor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public synchronized boolean hasData(){
        return !packets.isEmpty();
    }
    
    public void handlePackets(){
        List<Packet> previous = new ArrayList<>();
       
        synchronized(this){
            previous = packets;
            packets = new ArrayList<>();
        }
        
        for(Packet packet: previous){
            PacketInfo pdata = new PacketInfo(packet);
            try {
                List<SnortRule> matches = snort.match(pdata);
                if(!matches.isEmpty()){
                    System.out.println("matched "+ matches.size() + " rules");
                    for(SnortRule match: matches){
                        System.out.println(match);
                    }
                }
            } 
            catch (Exception ex) {
                Logger.getLogger(PcapMonitor.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public void run(){
        
        while(!interrupted()){
            loop();
        }
    }

    @Override
    public synchronized void gotPacket(Packet packet) {
        if(packet.get(IpPacket.class) != null){
            packets.add(packet);
            String protocol = packet.get(IpPacket.class).getHeader().getProtocol().name();
            switch(protocol){
               case "TCP":
                   tcpCount++;
                   break;
               case "UDP":
                   udpCount++;
                   break;

           }
        }    
    }
}
