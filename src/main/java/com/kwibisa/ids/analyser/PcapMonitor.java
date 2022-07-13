package com.kwibisa.ids.analyser;

import com.kwibisa.ids.ui.App;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import weka.core.Instance;
/**
 *
 * @author Kwibisa Mwene
 */
//Monitors traffic 
public class PcapMonitor extends Thread implements PacketListener {
    private List<Packet> packets = new ArrayList<>();
    private final MatchRules matchRules;
    ArrayList<Connection>connections = new ArrayList<>();
    HashMap<Connection, ArrayList<Packet>> packets2 = new HashMap<>();
    
    private static final int SNAPLEN = 65534;
    private static final int READ_TIMEOUT = 10;
    private static final int INFINITE = -1;
    private static final String FILTER = "ip";
    private final PcapNetworkInterface nif;
    private PcapHandle handle;
    private PcapDumper dumper;
    
    private final App app;
    private ClassifyInstance model;
    
    public PcapMonitor(PcapNetworkInterface nif, MatchRules matchRules, App app, ClassifyInstance model){
        this.matchRules = matchRules;
        this.nif = nif;
        this.app = app;
        this.model = model;
        initNif(nif);
    }
    
    private PcapHandle initNif(PcapNetworkInterface nif){
        try {
            handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            handle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);
            dumper = handle.dumpOpen("dumpfile.pcap");
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
    
    public void run(){
        while(!interrupted()){
            loop();
        }
    }

    @Override
    public synchronized void gotPacket(Packet packet) {
        packets.add(packet);
    }
    
    public void handlePackets(){
        List<Packet> previous = new ArrayList();
        List<Connection> prevCon = new ArrayList();
        synchronized(this){
            previous = packets;
            packets = new ArrayList<>();
            prevCon = connections;
            connections = new ArrayList<>();
        }
       //analyse current list of packets
       
        for(Packet packet: previous){
            PacketInfo pdata = new PacketInfo(packet);
            //handle connections
            handle(pdata, prevCon);
            try {
                List<Rule> matches = matchRules.match(pdata);
                if(!matches.isEmpty()){
                    System.out.println("matches size: "+matches.size());
                    //dumper.dump(packet);
                    //show match
                    for(Rule match: matches){
                        app.addRow(new Object[]{
                            match.getAlertType(),
                            pdata.getSrcAddr().getHostAddress(),
                            pdata.getSrcPort(),
                            pdata.protocol(),
                            pdata.getDstAddr().getHostAddress(),
                            pdata.getDstPort(),
                        });
                    }
                }
            } 
            catch (Exception ex) {
                Logger.getLogger(PcapMonitor.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        //classify connections
        for(Connection con: prevCon){
            Instance inst = model.buildInst(con.getProtocol(), con.getService(), con.getState(), con.getSrcBytes(), con.getDstBytes());
            if(model.predict(inst).equals("anomaly")){
                System.out.println(con.getProtocol());
                System.out.println(con.getService());
                System.out.println(con.getState());
                System.out.println(con.getSrcBytes());
                System.out.println(con.getDstBytes());
                
                if( true/*!(con.getSrcAddr().getHostAddress().equals("192.168.43.1") || con.getSrcAddr().getHostAddress().equals("192.168.43.89")) */){
                    app.addRow(new Object[]{
                    "Attempted Reconn",
                    con.getSrcAddr(),
                    con.getSrcPort(),
                    con.getProtocol(),
                    con.getDstAddr(),
                    con.getDstPort()
                    });
                }
                   
             con.getPackets().stream().forEach(e -> {
                /*try {
                    dumper.dump(e);
                } 
                catch (NotOpenException ex) {
                    Logger.getLogger(PcapMonitor.class.getName()).log(Level.SEVERE, null, ex);
                }*/
                });

                } 
            }
                
    }
    //handles connections
    private void handle(PacketInfo pdata, List<Connection> connections){
        for(Connection con: connections){
            if(con.equals(pdata.getConnectionInfo())){
                con.addPacket(pdata.getPacket());
                //connection exists |update connection
                if(con.getSrcAddr().equals(pdata.getSrcAddr())){
                    con.setSrcBytes(pdata.getPacket().getPayload().length());
                }
                else{
                    con.setDstBytes(pdata.getPacket().getPayload().length());
                }
                //update flags
                TcpPacket packet = pdata.getPacket().get(TcpPacket.class);
                if(packet != null){
                    TcpPacket.TcpHeader header = packet.getHeader();
                    if(con.getState().equals("S2") || con.getState().equals("S3") && header.getAck()){
                        con.setState("SF");
                    }
                    if(con.getState().equals("S0") && (header.getSyn()) && pdata.getSrcAddr().equals(con.getDstAddr())){
                        con.flow = Flow.SYN_ACKED;
                    }
                    if((con.flow == Flow.SYN_ACKED || con.flow == Flow.SYN) && header.getAck()){
                        con.setState("S1");
                    }
                    if(pdata.getSrcAddr().equals(con.getSrcAddr()) && header.getFin() && con.getState().equals("S0")){
                        con.setState("SH");
                    }
                    else if(pdata.getSrcAddr().equals(con.getSrcAddr()) && header.getRst() && con.flow == Flow.SYN){
                        con.setState("RSTOSO");
                    }
                    else if(con.getState().equals("S1") && header.getRst() && pdata.getSrcAddr().equals(con.getSrcAddr())){
                        con.setState("RSTO");
                    }
                    else if(con.getState().equals("S1") && header.getRst() && pdata.getSrcAddr().equals(con.getDstAddr())){
                        con.setState("RSTR");
                    }
                    else if(con.getState().equals("S1") && (header.getFin() && pdata.getSrcAddr().equals(con.getSrcAddr()))){
                        con.setState("S2");
                    }
                    else if(con.getState().equals("S1") && (header.getFin() && pdata.getSrcAddr().equals(con.getDstAddr()))){
                        con.setState("S3");
                    }
                }
            }
        }
        
        //new connections
        Connection c = pdata.getConnectionInfo();       
        //add new connection
        connections.add(c);
        c.addPacket(pdata.getPacket());
        //set source bytes | service|protocol|flag|dstbytes
        String protocol = pdata.protocol().name();
        if(protocol.equals("icmpv4"))
            protocol = "icmp";
        c.setProtocol(protocol);
        c.setService(pdata.getService());
        c.setState("SF");
        c.setSrcBytes(pdata.getPacket().getPayload().length());
        c.setDstBytes(0);
                
        TcpPacket packet = pdata.getPacket().get(TcpPacket.class);
        if(packet != null){
            TcpPacket.TcpHeader header = packet.getHeader();
            if(header.getPsh() || header.getUrg() || header.getAck() && !(header.getFin() || header.getSyn() || header.getRst())){
                c.setState("S1");
            }
            else if(header.getRst() && header.getAck()){
                c.setState("REJ");
            }
            else if(header.getSyn() && !header.getAck()){
                //connection attempt seen
                c.flow = Flow.SYN;
                c.setState("S0");
            }
        }
    }
}
