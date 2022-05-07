package com.km.ids;

import com.km.ids.analyser.snort.SnortMatcher;
import com.km.ids.data.PcapMonitor;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 *
 * @author Kwibisa Mwene
 */
public class IDS extends Thread{
    
    private List<PcapNetworkInterface> devices;
    private List<PcapMonitor> pcaps;
    private Main ui;
    private final SnortMatcher snort;
    
    private static long lastTime;
    private static long delta = 0;
    private static long dur = 5000;
    
    public IDS(Main ui, SnortMatcher snort){
        this.ui = ui;
        this.snort = snort;
    }

    private void capture(){
        boolean hasWork = false;
        for(PcapMonitor monitor: pcaps){
            if(monitor.hasData()){
                monitor.handlePackets();
                hasWork = true;
            }
        }
        if(!hasWork){
            try {
                Thread.sleep(100);
            } 
            catch (InterruptedException ex) {
                Logger.getLogger(IDS.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public void init(){
        System.out.println("Preparing to Listen to packets");
        try {
            devices = Pcaps.findAllDevs();
            pcaps = initNifs();
            System.out.println("Initialisation complete. Devices monitored: "+pcaps.size());
        } 
        catch (PcapNativeException ex) {
            Logger.getLogger(IDS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private List<PcapMonitor>initNifs(){
        List<PcapMonitor> handles = new ArrayList<>(devices.size());
        for(PcapNetworkInterface nif: devices){
            if(!nif.isLoopBack() && !nif.getAddresses().isEmpty()){
                PcapMonitor monitor = new PcapMonitor(nif,ui,snort);
                monitor.start();
                handles.add(monitor);
            }
        }
        return handles;
    }
    public void run(){
        lastTime = System.currentTimeMillis();
        init();
        while(!interrupted()){
            
            long current = System.currentTimeMillis();
            delta += current - lastTime;
            if(delta > dur){
               // ui.getUdp().setValue(PcapMonitor.udpCount+"");
               // ui.getTcp().setValue(PcapMonitor.tcpCount+"");
                //PcapMonitor.tcpCount = 0;
                //PcapMonitor.udpCount = 0;
                //PcapMonitor.icmpCnt = 0;
                delta = 0;
                lastTime = current;
            }
            
            capture();
            
        }
    }
    
}
