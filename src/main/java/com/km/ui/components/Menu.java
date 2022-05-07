package com.km.ui.components;

import com.km.ui.event.MenuEvent;
import com.km.ui.swing.MenuButton;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.RenderingHints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

/**
 *
 * @author Kwibisa Mwene
 */
public class Menu extends javax.swing.JPanel {

   private MenuEvent event;
    public Menu() {
        initComponents();
        setOpaque(false);
        scroll.setViewportBorder(null);
        scroll.setBorder(null);
        scroll.getViewport().setOpaque(false);
        menuPanel.setLayout(new BoxLayout(menuPanel, BoxLayout.Y_AXIS));
        
        
    }

    
    public void initMenu(MenuEvent event){
        this.event = event;
        addMenu("", "Dashboard", 0);
        addMenu("", "Alerts", 1);
        addMenu("", "Settings", 2);
        addMenu("", "Stats", 3);
        addMenu("", "Dashboard", 4);
        addMenu("", "Dashboard", 5);
        addMenu("", "Dashboard", 6);
        addMenu("", "Dashboard", 7);
        addMenu("", "Dashboard", 8);
        addMenu("", "Dashboard", 9);
        addMenu("", "Dashboard", 10);
        
    }
    private void addMenu(String icon, String title, int index){
        MenuButton menu = new MenuButton(index);
        menu.setFont(menu.getFont().deriveFont(Font.PLAIN,14));
        menu.setText(" "+title);
        menu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                event.menuSelected(index);
            }
        });
        menuPanel.add(menu);
        
      
    }
    
    @Override
    public void paint(Graphics graphics){
        Graphics2D g2d = (Graphics2D) graphics.create();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        double width = getWidth();
        double height = getHeight();

        super.paint(graphics);
    }
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        logo = new javax.swing.JLabel();
        scroll = new javax.swing.JScrollPane();
        menuPanel = new javax.swing.JPanel();

        logo.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        logo.setForeground(new java.awt.Color(255, 255, 255));
        logo.setText("Dashboard");
        logo.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 10, 1, 1));

        menuPanel.setOpaque(false);

        javax.swing.GroupLayout menuPanelLayout = new javax.swing.GroupLayout(menuPanel);
        menuPanel.setLayout(menuPanelLayout);
        menuPanelLayout.setHorizontalGroup(
            menuPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 208, Short.MAX_VALUE)
        );
        menuPanelLayout.setVerticalGroup(
            menuPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 305, Short.MAX_VALUE)
        );

        scroll.setViewportView(menuPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(logo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(scroll)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(logo, javax.swing.GroupLayout.PREFERRED_SIZE, 47, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(scroll))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel logo;
    private javax.swing.JPanel menuPanel;
    private javax.swing.JScrollPane scroll;
    // End of variables declaration//GEN-END:variables
}
