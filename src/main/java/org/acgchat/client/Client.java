package org.acgchat.client;

import org.acgchat.common.ChatMessage;
import org.acgchat.common.Logger;
import org.bouncycastle.crypto.tls.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Created by NEOPETS on 18/1/2017.
 */
public class Client extends Logger {

    private String server;
    private int port;
    private X509Certificate caCertificate;
    private Socket socket;
    private TlsClientProtocol tlsClientProtocol;
    private ObjectInputStream sInput;
    private ObjectOutputStream sOutput;

    Client(String server, int port, String cacert, String username) throws CertificateException, IOException {
        info("Client will listen to: " + server + ":" + port);
        this.server = server;
        this.port = port;

        info("Loading in certificate authority's certificate...");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(cacert);
        caCertificate = (X509Certificate) factory.generateCertificate(fis);
        fis.close();
        info("Load completed.");

    }

    public boolean start() {
        info("Connecting to the server...");
        try {
            socket = new Socket(server, port);
            tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
            tlsClientProtocol.connect(new DefaultTlsClient() {
                public TlsAuthentication getAuthentication() throws IOException {
                    return new ServerOnlyTlsAuthentication() {
                        public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
                            try {
                                X509Certificate serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(serverCertificate.getCertificateList()[0].getEncoded()));
                                verifyCertificates(caCertificate, serverCert);
                            } catch (CertificateException e) {
                                error("Unable to verify server's ceritifcate: " + e);
                                e.printStackTrace();
                            }
                        }
                    };
                }
            });
            sOutput = new ObjectOutputStream(tlsClientProtocol.getOutputStream());
            sOutput.flush();
            sInput = new ObjectInputStream(tlsClientProtocol.getInputStream());
        } catch (IOException e) {
            error("Unable to connect to server: " + e);
            e.printStackTrace();
            return false;
        }
        info("Connection complete. Listening from server.");
        new ListenFromServer().start();
        return true;
    }

    private void sendMessage(ChatMessage chatMessage) {
        try {
            sOutput.writeObject(chatMessage);
        } catch (IOException e) {
            error("Exception writing to server: " + e);
            e.printStackTrace();
        }
    }/*
     * When something goes wrong
     * Close the Input/Output streams and disconnect not much to do in the catch clause
     */
    private void disconnect() {
        try {
            if (sInput != null) sInput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (sOutput != null) sOutput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (tlsClientProtocol != null) tlsClientProtocol.close();
        } catch (Exception e) {
        }
        try {
            if (socket != null) socket.close();
        } catch (Exception e) {
        } // not much else I can do

        warning("Disconnected from the server.");
    }

    public static void main(String[] args) {
        // default values
        int portNumber = 1500;
        String serverAddress = "localhost";
        String userName = "Anonymous";

        // depending of the number of arguments provided we fall through
        switch (args.length) {
            // > javac Client username portNumber serverAddr
            case 3:
                serverAddress = args[2];
                // > javac Client username portNumber
            case 2:
                try {
                    portNumber = Integer.parseInt(args[1]);
                } catch (Exception e) {
                    System.out.println("Invalid port number.");
                    System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
                    return;
                }
                // > javac Client username
            case 1:
                userName = args[0];
                // > java Client
            case 0:
                break;
            // invalid number of arguments
            default:
                System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
                return;
        }
        // create the Client object
        Client client = null;
        try {
            client = new Client(serverAddress, portNumber,"ACGChatCA.cert", userName);
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }
        // test if we can start the connection to the Server
        // if it failed nothing we can do
        if (!client.start())
            return;

        // wait for messages from user
        Scanner scan = new Scanner(System.in);
        // loop forever for message from the user
        while (true) {
            System.out.print("> ");
            // read message from user
            String msg = scan.nextLine();
            // logout if message is LOGOUT
            if (msg.equalsIgnoreCase("/logout")) {
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.LOGOUT, userName, ""));
                // break to do the disconnect
                break;
            }
            // message WhoIsIn
            else if (msg.equalsIgnoreCase("/whoisin")) {
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, userName, ""));
            } else {                // default to ordinary message
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.MESSAGE, userName, msg));
            }
        }
        // done disconnect
        client.disconnect();
    }

    private static void verifyCertificates(X509Certificate CACert, X509Certificate serverCert) throws CertificateException {
        if (CACert == null || serverCert == null) {
            throw new IllegalArgumentException("Certificate not found");
        }
        if (!CACert.equals(serverCert)) {
            try {
                serverCert.verify(CACert.getPublicKey());
            } catch (Exception e) {
                throw new CertificateException("Certificate not trusted", e);
            }
        }
        try {
            serverCert.checkValidity();
        } catch (Exception e) {
            throw new CertificateException("Certificate not trusted. It has expired", e);
        }
    }

    /*
 * a class that waits for the message from the server and append them to the JTextArea
 * if we have a GUI or simply System.out.println() it in console mode
 */
    class ListenFromServer extends Thread {

        public void run() {
            while (true) {
                try {
                    ChatMessage msg = (ChatMessage) sInput.readObject();
                    // if console mode print the message and add back the prompt
                    chat(msg.getUser() + ": " + msg.getMessage());
                    System.out.print("> ");
                } catch (IOException e) {
                    error("Server has close the connection: " + e);
                    System.exit(0);
                }
                // can't happen with a String object but need the catch anyhow
                catch (ClassNotFoundException e2) {
                }
            }
        }
    }

}
