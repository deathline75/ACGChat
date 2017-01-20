package org.acgchat.server;

import org.acgchat.common.ChatMessage;
import org.acgchat.common.Logger;
import org.apache.commons.cli.*;
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
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private File credentials;
    private ConcurrentHashMap<String, String> users;

    protected Server(int port, String credentialPath, String keystorePath, String keystorePassword, String alias, String aliasPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        info("Server will start on port: " + port);
        this.port = port;

        info("Loading credentials file...");
        credentials = new File(credentialPath);
        if (!credentials.exists()) {
            warning("File does not exist. Creating new file");
            credentials.createNewFile();
        }

        FileReader fr = new FileReader(credentials);
        BufferedReader br = new BufferedReader(fr);

        users = new ConcurrentHashMap<>();

        String currentLine;
        while ((currentLine = br.readLine()) != null) {
            Pattern pattern = Pattern.compile("([a-zA-Z0-9]+):(.*)");
            Matcher m = pattern.matcher(currentLine);
            if (m.find())
                users.put(m.group(1), m.group(2));
        }

        info("Found: " + users.size() + " users");
        br.close();
        fr.close();

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
                    break;
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

        // Initialize all the options that are avaliable
        Option portOption = Option.builder("p").argName("port").longOpt("port").desc("port number to bind to").hasArg().build();
        Option credentialsOption = Option.builder("c").argName("file").longOpt("credential").desc("credential file to use").hasArg().build();
        Option keystorePathOption = Option.builder("k").argName("file").longOpt("keystore").desc("location of keystore").hasArg().build();
        Option keystorePasswordOption = Option.builder("kp").argName("password").longOpt("keystore-password").desc("password of keystore").hasArg().build();
        Option aliasOption = Option.builder("a").argName("alias").longOpt("alias").desc("alias to use in keystore").hasArg().build();
        Option aliasPasswordOption = Option.builder("ap").argName("password").longOpt("alias-password").desc("alias password for alias to use in keystore").hasArg().build();

        // Group keystore together
        OptionGroup keystoreOptionGroup = new OptionGroup();
        keystoreOptionGroup.addOption(keystorePathOption);
        keystoreOptionGroup.addOption(keystorePasswordOption);

        // Group alias together
        OptionGroup aliasOptionGroup = new OptionGroup();
        aliasOptionGroup.addOption(aliasOption);
        aliasOptionGroup.addOption(aliasPasswordOption);

        // Add all the options into options.
        Options options = new Options();
        options.addOption(portOption);
        options.addOption(credentialsOption);
        options.addOptionGroup(keystoreOptionGroup);
        options.addOptionGroup(aliasOptionGroup);

        // Initialize the parsers and helpers
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        // Try to understand the arguments entered
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            // Prints out help message if cannot understand
            System.out.println(e.getMessage());
            formatter.printHelp("Server", options);

            System.exit(1);
            return;
        }

        Server server = null;
        try {
            // Start the server based on arguments
            int port = Integer.parseInt(cmd.getOptionValue("port", "1500"));
            server = new Server(port,
                    cmd.getOptionValue("credential", "Credentials"),
                    cmd.getOptionValue("keystore", "ACGChatKeystore.pfx"),
                    cmd.getOptionValue("keystore-password", "1qwer$#@!"),
                    cmd.getOptionValue("alias", "ACGChatServerSigned"),
                    cmd.getOptionValue("alias-password", "1qwer$#@!"));
            server.start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
