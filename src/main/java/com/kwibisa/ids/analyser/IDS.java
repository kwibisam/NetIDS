package com.kwibisa.ids.analyser;

import com.kwibisa.ids.ui.App;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 *
 * @author Kwibisa Mwene
 */
public class IDS extends Thread{
    
    private List<PcapNetworkInterface> devices;
    private List<PcapMonitor> pcaps;
    private MatchRules matchRules;
    private final App app;
    private ClassifyInstance model;
   
    public IDS(App app){
        this.app = app;
    }

    public void init(MatchRules matchRules, ClassifyInstance model){
       this.matchRules = matchRules;
       this.model = model;
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
        
        try {
            devices = Pcaps.findAllDevs();
            pcaps = initNifs();
        } 
        catch (Exception ex) {
            Logger.getLogger(IDS.class.getName()).log(Level.SEVERE, null, ex);
            JOptionPane.showMessageDialog(null,""+ IDS.class.getName() + ex,"Warning",1);
        }
    }
    
    private List<PcapMonitor>initNifs(){
        List<PcapMonitor> handles = new ArrayList<>(devices.size());
        for(PcapNetworkInterface nif: devices){
            if(!nif.isLoopBack() && !nif.getAddresses().isEmpty()){
                PcapMonitor monitor = new PcapMonitor(nif,matchRules, app, model);
                monitor.start();
                handles.add(monitor);
            }
        }
        return handles;
    }
    
    public void run(){
        init();
        while(!interrupted()){ 
            capture();
            
        }
    }
    
}
