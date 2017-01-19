package org.acgchat.server;

import org.acgchat.common.ChatMessage;
import org.acgchat.common.Logger;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;

/**
 * Created by NEOPETS on 18/1/2017.
 */
public class Server extends Logger {

    private static int idGenerator = 0;
    private int port;
    private KeyPair keyPair;
    private Certificate certificate;
    private boolean keepGoing = true;
    private HashMap<Integer, ClientThread> clients;

    protected Server(int port, String keystorePath, String keystorePassword, String alias, String aliasPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        info("Server will start on port: " + port);
        this.port = port;
        info("Loading keystore...");
        FileInputStream is = new FileInputStream(keystorePath);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(is, "1qwer$#@!".toCharArray());
        info("Initializing private key...");
        Key key = keyStore.getKey(alias, aliasPassword.toCharArray());
        if (key instanceof PrivateKey) {
            info("Initializing certificate for the server...");
            certificate = keyStore.getCertificate(alias);
            PublicKey publicKey = certificate.getPublicKey();
            keyPair = new KeyPair(publicKey, (PrivateKey) key);
        } else {
            throw new UnrecoverableKeyException("Cannot get private key out of keystore!");
        }
        clients = new HashMap<Integer, ClientThread>();
        info("Loading completed!");
    }

    protected void start() {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            info("----------");
            info("Server has started listening for client connections.");
            while (keepGoing) {
                Socket s = serverSocket.accept();
                if (!keepGoing)
                    break;
                ClientThread newClient = new ClientThread(s);
                if (newClient.running) {
                    info("Client #" + newClient.getClientThreadId() + " (" + s.getRemoteSocketAddress().toString() + ") has attempted to connect.");
                    clients.put(newClient.getClientThreadId(), newClient);
                    newClient.start();
                } else {
                    newClient.close();
                }
            }
            warning("Server is closing...");
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private synchronized void broadcast(ChatMessage message) {
        // display message on console or GUI
        chat(message.getUser() + ": " + message.getMessage());
        // we loop in reverse order in case we would have to remove a Client
        // because it has disconnected
        for (ClientThread ct : clients.values()) {
            if (!ct.writeMsg(message)) {
                remove(ct.getClientThreadId());
                info("Disconnected Client #" + ct.getClientThreadId() + " removed from list.");
            }
        }
    }

    synchronized void remove(int ctid) {
        clients.remove(ctid);
    }

    class ClientThread extends Thread {

        int ctid;
        Socket socket;
        TlsServerProtocol tlsServerProtocol;
        ObjectInputStream sInput;
        ObjectOutputStream sOutput;
        boolean running = false;

        ClientThread(Socket socket) {
            this.ctid = idGenerator++;
            this.socket = socket;
            try {
                final org.bouncycastle.asn1.x509.Certificate bcCert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1TaggedObject.fromByteArray(certificate.getEncoded()));
                tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
                tlsServerProtocol.accept(new DefaultTlsServer() {
                    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
                        return new DefaultTlsSignerCredentials(context, new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{bcCert}), PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));
                    }
                });
                sOutput = new ObjectOutputStream(tlsServerProtocol.getOutputStream());
                sOutput.flush();
                sInput = new ObjectInputStream(tlsServerProtocol.getInputStream());
                running = true;
            } catch (IOException | CertificateEncodingException e) {
                error("Unable to establish secure connection.");
                e.printStackTrace();
            }

        }

        public void run() {
            while (running) {
                try {
                    ChatMessage chatMessage = (ChatMessage) sInput.readObject();
                    switch (chatMessage.getType()) {
                        case MESSAGE:
                            broadcast(chatMessage);
                            break;
                        case COMMAND:
                            break;
                        case LOGIN:
                            break;
                        case LOGOUT:
                            info(chatMessage.getUser() + " has disconnected from the server.");
                            running = false;
                            break;
                        case REGISTER:
                            break;
                        case ERROR:
                        case SUCCESS:
                        default:
                            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "Invalid or unsupported message type!"));
                    }
                } catch (IOException | ClassNotFoundException e) {
                    error("Error when receiving a new message: " + e);
                    e.printStackTrace();
                }
            }
            remove(getClientThreadId());
            close();
        }

        public int getClientThreadId() {
            return ctid;
        }

        public void close() {
            try {
                sInput.close();
            } catch (IOException e) {
            }
            try {
                sOutput.close();
            } catch (IOException e) {
            }
            try {
                tlsServerProtocol.close();
            } catch (IOException e) {
            }
            try {
                socket.close();
            } catch (IOException e) {
            }
        }

        public boolean writeMsg(ChatMessage message) {
            if (tlsServerProtocol.isClosed()) {
                close();
                return false;
            }

            try {
                sOutput.writeObject(message);
                sOutput.flush();
            } catch (IOException e) {
                error("Unable to send message: " + e);
                e.printStackTrace();
                return false;
            }
            return true;
        }
    }

    public static void main(String[] args) {
        Server server = null;
        try {
            if (args.length == 0) {
                server = new Server(1500, "ACGChatKeystore.pfx", "1qwer$#@!", "ACGChatServerSigned", "1qwer$#@!");
            } else if (args.length == 1 && args[0].matches("^[0-9]{1,5}$")) {
                int port = Integer.parseInt(args[0]);
                if (port <= 65535) {
                    server = new Server(port, "ACGChatKeystore.pfx", "1qwer$#@!", "ACGChatServerSigned", "1qwer$#@!");
                }
            } else {
                System.out.println("Usage: <filename> [port]");
                return;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        server.start();
    }

}
