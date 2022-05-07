package com.km.ui.swing;

import com.km.ui.event.MenuEvent;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.border.EmptyBorder;

/**
 *
 * @author Kwibisa Mwene
 */
public class MenuButton extends JButton {

    private float animate;
    private int index;

    public float getAnimate() {
        return animate;
    }

    public void setAnimate(float animate) {
        this.animate = animate;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }
    
    public MenuButton(int index) {
        this.index = index;
        setContentAreaFilled(false);
        setForeground(new Color(109,109,109));
        setCursor(new Cursor(Cursor.HAND_CURSOR));
        setBackground(new Color(65,65,65));
        setBorder(new EmptyBorder(8,20,8,15));
        
        
    }
    
}
