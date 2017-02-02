package org.acgchat.server;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by Kelvin on 16/1/2017.
 */
public class ServerGUI{
    private JTextField portTextField;
    private JButton startButton;
    private JTextArea chatTextArea;
    private JTextArea consoleTextArea;
    private JTabbedPane tabbedPane1;
    private JTextField credentialFileTextField;
    private JTextField keystoreLocationTextField;
    private JPasswordField keystorePasswordField;
    private JTextField aliasNameTextField;
    private JPasswordField aliasPasswordField;
    private JPanel mainPanel;
    private ServerGUIObject guiObject;

    public ServerGUI() {
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (guiObject == null) {
                    consoleTextArea.setText("");
                    if (!portTextField.getText().matches("^[0-9]{1,5}$"))
                        consoleTextArea.append(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - [ERROR] Invalid port number!\n");
                    else {
                        try {
                            setFieldStates(false);
                            guiObject = new ServerGUIObject(Integer.parseInt(portTextField.getText()),
                                    credentialFileTextField.getText(),
                                    keystoreLocationTextField.getText(),
                                    new String(keystorePasswordField.getPassword()),
                                    aliasNameTextField.getText(),
                                    new String(aliasPasswordField.getPassword()));
                            new ServerGUIThread().start();
                            startButton.setEnabled(true);
                            startButton.setText("Stop");
                        } catch (IOException | KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException e1) {
                            consoleTextArea.append(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - [ERROR] An error occurred: + " + e1 + "\n");
                            e1.printStackTrace();
                            startButton.setEnabled(true);
                        }
                    }
                } else {
                    guiObject.stop();
                }
            }
        });
    }

    private void setFieldStates(boolean state) {
        startButton.setEnabled(state);
        portTextField.setEditable(state);
        credentialFileTextField.setEditable(state);
        keystoreLocationTextField.setEditable(state);
        keystorePasswordField.setEditable(state);
        aliasNameTextField.setEditable(state);
        aliasPasswordField.setEditable(state);
    }

    public class ServerGUIThread extends Thread {
        public void run() {
            guiObject.start();
            guiObject = null;
            startButton.setText("Start");
            setFieldStates(true);
            consoleTextArea.append(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - [WARNING] The server crashed or stopped.\n");
        }
    }

    public class ServerGUIObject extends Server{

        protected ServerGUIObject(int port, String credentialPath, String keystorePath, String keystorePassword, String alias, String aliasPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
            super(port, credentialPath, keystorePath, keystorePassword, alias, aliasPassword);
        }

        @Override
        public void log(String type, String message) {
            consoleTextArea.append(simpleDateFormat.format(new Date()) + " - [" + type + "] " + message + "\n");
            consoleTextArea.setCaretPosition(consoleTextArea.getText().length() - 1);
            System.out.println(simpleDateFormat.format(new Date()) + " - [" + type + "] " + message);
        }

        @Override
        public void info(String message) {
            log("INFO", message);
        }

        @Override
        public void debug(String message) {
            log("DEBUG", message);
        }

        @Override
        public void chat(String message) {
            chatTextArea.append(simpleDateFormat.format(new Date()) + " - " + message + "\n");
            chatTextArea.setCaretPosition(chatTextArea.getText().length() - 1);
        }

        @Override
        public void warning(String message) {
            log("WARNING", message);
        }

        public void error(String message) {
            log("ERROR", message);
        }
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("ServerGUI");
        final ServerGUI serverGUI = new ServerGUI();
        frame.setContentPane(serverGUI.mainPanel);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
        frame.addWindowListener(new WindowListener() {
            public void windowOpened(WindowEvent e) {}
            @Override
            public void windowClosing(WindowEvent e) {
                if (serverGUI.guiObject != null) {
                    serverGUI.guiObject.stop();
                }
                serverGUI.guiObject = null;
                System.exit(0);
            }
            public void windowClosed(WindowEvent e) {}
            public void windowIconified(WindowEvent e) {}
            public void windowDeiconified(WindowEvent e) {}
            public void windowActivated(WindowEvent e) {}
            public void windowDeactivated(WindowEvent e) {}
        });
    }


}
