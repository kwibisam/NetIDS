package com.km.ids;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.LayoutManager;
import javax.swing.GroupLayout;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 *
 * @author Kwibisa Mwene
 */
public class Frame extends JFrame {
    private JPanel mainPanel;
    
    public Frame(){
        mainPanel = new JPanel();
        mainPanel.setPreferredSize(new Dimension(1080,600));
        mainPanel.setSize(getPreferredSize());
        mainPanel.setBackground(new Color(50,50,50));
        //LayoutManager gl = new GroupLayout(mainPanel);
        //LayoutManager bl = new BorderLayout();
        LayoutManager grl = new GridLayout(2,1);
        mainPanel.setLayout(grl);
        
        JPanel top = new JPanel();
        top.setBackground(Color.red);
        top.add(new JLabel("TOP"));
                
        JPanel bot = new JPanel();
        bot.setBackground(Color.green);
        bot.add(new JLabel("Bottom"));
        
        mainPanel.add(top);
        mainPanel.add(bot);
                
        add(mainPanel);
        
    }
}
