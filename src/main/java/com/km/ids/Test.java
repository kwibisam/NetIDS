package com.km.ids;


import com.km.ids.data.PcapMonitor;
import static java.lang.Thread.interrupted;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 *
 * @author Kwibisa Mwene
 */
public class Test {
    public static void main(String args[]) throws PcapNativeException{
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
               Frame frame = new Frame();
               frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
               frame.pack();
               frame.setVisible(true);
            }
        });
        
       List<PcapNetworkInterface> nifs = new ArrayList<>();
       nifs = Pcaps.findAllDevs();
       List<PcapMonitor> handles = new ArrayList<>(nifs.size());
       for(PcapNetworkInterface nif: nifs){
           if(!nif.isLoopBack() && !nif.getAddresses().isEmpty()){
               //PcapMonitor mon = new PcapMonitor(nif);
               //mon.start();
               //handles.add(mon);
           }
       }
       
       while(!interrupted()){
           boolean hasWork = false;
           for(PcapMonitor mon: handles){
               if(mon.hasData()){
                  mon.handlePackets();
                  hasWork = true;
               }
           }
           
           if(!hasWork){
               try {
                   Thread.sleep(100);
               } 
               catch (InterruptedException ex) {
                   Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
               }
           }
       }
       
    }
}
