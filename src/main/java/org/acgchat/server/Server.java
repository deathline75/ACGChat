package org.acgchat.server;

import org.acgchat.common.ChatMessage;
import org.acgchat.common.Command;
import org.acgchat.common.CommandsHandler;
import org.acgchat.common.Logger;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.crypto.tls.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.cert.Certificate;

/**
 * The command-line interface and logic of the server.
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class Server extends Logger {

    private static final int hashIterations = 200000;
    private static int idGenerator = 0;
    private int port;
    private KeyPair keyPair;
    private Certificate certificate;
    private boolean keepGoing = true;
    private HashMap<Integer, ClientThread> clients;
    private File credentials;
    private ConcurrentHashMap<String, String> users;
    private ConcurrentHashMap<String, Integer> loggedIn = new ConcurrentHashMap<>();

    /**
     * Initialize the Server object.
     * @param port The port number to start the server on
     * @param credentialPath The path to the credentials file for users
     * @param keystorePath The path the the keystore where the private keys are located at.
     * @param keystorePassword The password of the keystore.
     * @param alias The alias of the server's private key
     * @param aliasPassword The password of the alias
     * @throws IOException When any file cannot be read or written to properly
     * @throws KeyStoreException When the keystore cannot be initialized properly
     * @throws CertificateException When the certificate cannot be initialized properly from the keystore
     * @throws NoSuchAlgorithmException When the algorithm used is not found
     * @throws UnrecoverableKeyException When the key is stuck in a false vacuum
     */
    protected Server(int port, String credentialPath, String keystorePath, String keystorePassword, String alias, String aliasPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        info("Server will start on port: " + port);
        this.port = port;

        // Load the credentials file
        info("Loading credentials file...");
        credentials = new File(credentialPath);
        if (!credentials.exists()) {
            warning("File does not exist. Creating new file");
            credentials.createNewFile();
        }

        FileReader fr = new FileReader(credentials);
        BufferedReader br = new BufferedReader(fr);

        // Store the users into a HashMap with their passwords
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

        // Load the keystore using PKCS#12.
        info("Loading keystore...");
        FileInputStream is = new FileInputStream(keystorePath);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(is, keystorePassword.toCharArray());

        // Get the private key of the server out of the keystore
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
        // Create a new hashmap to store all the connection threads of all clients connected.
        clients = new HashMap<Integer, ClientThread>();
        info("Loading completed!");
    }

    /**
     * Start the server.
     */
    protected void start() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Start the socket that will accept connections from clients
            ServerSocket serverSocket = new ServerSocket(port);
            info("----------");
            info("Server has started listening for client connections.");
            while (keepGoing) {
                // Generate the socket unique to the client and pass it to ClientThread to handle the rest.
                Socket s = serverSocket.accept();
                if (!keepGoing)
                    break;
                ClientThread newClient = new ClientThread(s);
                newClient.start();
            }
            // Close all the client threads when keepGoing is false.
            warning("Server is closing...");
            for (ClientThread ct: clients.values()) {
                ct.close();
            }
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * Stop the server
     */
    protected void stop() {
        keepGoing = false;
        // connect to myself as Client to exit statement
        // Socket socket = serverSocket.accept();
        try {
            new Socket("localhost", port);
        } catch (Exception e) {
            // nothing I can really do
        }
    }

    /**
     * Broadcast the message to all of the users online.
     * @param message The message to broadcast
     */
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

    /**
     * Remove a client from the server pool
     * @param ctid The unique client ID assigned
     */
    synchronized void remove(int ctid) {
        loggedIn.remove(clients.get(ctid).getUser());
        clients.remove(ctid);
    }

    /**
     * Get the instance of the server
     * @return The server
     */
    private Server getServer() {
        return this;
    }

    /**
     * Get the login users along with their client thread
     * @return The login users along with their client thread
     */
    public ConcurrentHashMap getLoggedIn() {
        return this.loggedIn;
    }

    public ClientThread getUser(String username) {
        return this.clients.get(this.loggedIn.get(username));
    }

    /**
     * The thread used to handle each client individually.
     */
    public class ClientThread extends Thread {

        int ctid;
        Socket socket;
        TlsServerProtocol tlsServerProtocol;
        ObjectInputStream sInput;
        ObjectOutputStream sOutput;
        boolean running = false;
        String user = null;

        /**
         * Initialize the ClientThread
         * @param socket The socket that is given from the server that is unique to this client
         */
        ClientThread(Socket socket) {
            this.ctid = idGenerator++;
            this.socket = socket;


        }

        /**
         * Start running the thread to check for new messages sent from the client.
         */
        public void run() {
            try {
                // Start the TLS handshake with the client
                final org.bouncycastle.asn1.x509.Certificate bcCert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1TaggedObject.fromByteArray(certificate.getEncoded()));
                tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
                DefaultTlsServer defaultTlsServer = new DefaultTlsServer() {

                    protected ProtocolVersion getMaximumVersion() {
                        return ProtocolVersion.TLSv12;
                    }

                    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
                        SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) TlsUtils.getDefaultRSASignatureAlgorithms().get(0);
                        return new DefaultTlsSignerCredentials(context,
                                new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{bcCert}),
                                PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()),
                                signatureAndHashAlgorithm);
                    }
                };
                tlsServerProtocol.accept(defaultTlsServer);
                // See: https://www.bouncycastle.org/docs/tlsdocs1.5on/constant-values.html#org.bouncycastle.tls.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                debug(String.format("Selected Cipher: %d (0x%x)", defaultTlsServer.getSelectedCipherSuite(), defaultTlsServer.getSelectedCipherSuite()));

                // If the handshake was successful, use the new socket streams to communicate with the clients securely
                sOutput = new ObjectOutputStream(tlsServerProtocol.getOutputStream());
                sOutput.flush();
                sInput = new ObjectInputStream(tlsServerProtocol.getInputStream());

                try {
                    // Attempt to read if the first message is login or register.
                    ChatMessage chatMessage = (ChatMessage) sInput.readObject();
                    switch (chatMessage.getType()) {
                        case REGISTER:
                            // Check if the user already exists
                            if (!users.containsKey(chatMessage.getUser()) && !loggedIn.containsKey(chatMessage.getUser())) {
                                // Generate the salt
                                byte[] salt = new byte[16];
                                SecureRandom random = new SecureRandom();
                                random.nextBytes(salt);
                                // Hash it with the salt and convert both to Base64 to store inside the credentials file
                                long start = System.currentTimeMillis();
                                String hashed = DatatypeConverter.printBase64Binary(hashPassword(((String)chatMessage.getMessage()).toCharArray(), salt, hashIterations, 512));
                                long end = System.currentTimeMillis();
                                debug("Time taken to hash: " + (end-start) + " ms");
                                String salt64 = DatatypeConverter.printBase64Binary(salt);

                                users.put(chatMessage.getUser(), salt64 + ';' + hashed);
                                updateCredentialsFile();

                                // Assign this ClientThread to this username
                                user = chatMessage.getUser();
                                info("Client #" + getClientThreadId() + " registered a new user: " + user);

                                sOutput.writeObject(new ChatMessage(ChatMessage.ChatMessageType.SUCCESS, chatMessage.getUser(), "Registration successful!"));
                                running = true;
                            } else {
                                // Otherwise, delay the connection a bit and send back an error message
                                byte[] salt = new byte[16];
                                SecureRandom random = new SecureRandom();
                                random.nextBytes(salt);
                                String hashed = DatatypeConverter.printBase64Binary(hashPassword(((String)chatMessage.getMessage()).toCharArray(), salt, hashIterations, 512));
                                String salt64 = DatatypeConverter.printBase64Binary(salt);
                                warning("Client (" + socket.getRemoteSocketAddress().toString() + ") attempted to create an existing user.");
                                writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "Unable to register username."));
                            }
                            break;
                        case LOGIN:
                            // Check if the user exists
                            if (users.containsKey(chatMessage.getUser()) && !loggedIn.containsKey(chatMessage.getUser())) {
                                // Attempt to check if the password provided is correct
                                String[] combo = users.get(chatMessage.getUser()).split(";");
                                long start = System.currentTimeMillis();
                                byte[] hashedInput = hashPassword(((String)chatMessage.getMessage()).toCharArray(), DatatypeConverter.parseBase64Binary(combo[0]), hashIterations, 512);
                                long end = System.currentTimeMillis();
                                debug("Time taken to hash: " + (end-start) + " ms");
                                if (Arrays.equals(hashedInput, DatatypeConverter.parseBase64Binary(combo[1]))){
                                    // User logs in successfully
                                    user = chatMessage.getUser();
                                    info("Client #" + getClientThreadId() + " has logged in as: " + user);
                                    sOutput.writeObject(new ChatMessage(ChatMessage.ChatMessageType.SUCCESS, chatMessage.getUser(), "Login successful!"));
                                    running = true;
                                    break;
                                }
                            } else {
                                hashPassword(((String)chatMessage.getMessage()).toCharArray(), DatatypeConverter.parseBase64Binary("asdf"), hashIterations, 512);
                            }
                            warning("Client (" + socket.getRemoteSocketAddress().toString() + ") supplied wrong credentials when logging in.");
                            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "Invalid username or password!"));
                            close();
                            return;
                        default:
                            warning("Client (" + socket.getRemoteSocketAddress().toString() + ") attempted to forge a packet: " + chatMessage.toString());
                            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "Invalid or unsupported message type!"));
                            close();
                            return;
                    }

                } catch (ClassNotFoundException e) {
                    writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, "", "Internal error occurred."));
                    e.printStackTrace();
                    close();
                    return;
                }

            } catch (IOException | CertificateEncodingException e) {
                error("Unable to establish secure connection.");
                e.printStackTrace();
                close();
                return;
            }

            info("Client #" + getClientThreadId() + " (" + socket.getRemoteSocketAddress().toString() + ") has attempted to connect.");
            clients.put(getClientThreadId(), this);
            loggedIn.put(getUser(), getClientThreadId());
            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.MESSAGE, "SYSTEM", "Welcome: " + user + "!"));
            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.MESSAGE, "SYSTEM", "Type '/help' to see the list of commands"));
            try {
                updateCredentialsFile();
            } catch (IOException e) {
                error("Unable to update credentials file.");
                e.printStackTrace();
                close();
                return;
            }

            while (running) {
                try {
                    ChatMessage chatMessage = (ChatMessage) sInput.readObject();
                    // Check the type of message sent
                    switch (chatMessage.getType()) {
                        case MESSAGE:
                            // Broadcast the message to the server if logged in.
                            if (user != null)
                                broadcast(chatMessage);
                            else
                                writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "You are not logged in!"));
                            break;
                        case COMMAND:
                            // Handle commands sent by user
                            chat(chatMessage.getUser() + ": /" + chatMessage.getMessage());
                            Command command = CommandsHandler.getCommand((String) chatMessage.getMessage());
                            String regex = "\"([^\"]*)\"|(\\S+)";
                            Matcher m = Pattern.compile(regex).matcher((String) chatMessage.getMessage());
                            List<String> list = new ArrayList<>();
                            while (m.find())
                                list.add(m.group(1) != null ? m.group(1) : m.group(2));
                            if (command != null) {
                                if (!command.execute(getServer(), this, list.toArray(new String[list.size()]))) {
                                    error(chatMessage.getUser() + "'s command failed.");
                                    writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, "SYSTEM", "Invalid command syntax!"));
                                }
                            } else {
                                broadcast(chatMessage);
                            }
                            break;
                        case LOGOUT:
                            // Log the user out of the server
                            info("Client #" + getClientThreadId() + " (" + getUser() + ") has disconnected from the server.");
                            running = false;
                            break;
                        case LOGIN:
                        case REGISTER:
                        case ERROR:
                        case SUCCESS:
                        default:
                            // Just send invalid message if wrong message is received
                            writeMsg(new ChatMessage(ChatMessage.ChatMessageType.ERROR, chatMessage.getUser(), "Invalid or unsupported message type!"));
                    }
                } catch (SocketException e)  {
                    if (e.getMessage().startsWith("Connection reset by peer") || e.getMessage().startsWith("Socket closed")) {
                        info("Client #" + getClientThreadId() + " (" + getUser() + ") has disconnected from the server.");
                        running = false;
                    } else {
                        error("Error when receiving a new message: " + e);
                        e.printStackTrace();
                        break;
                    }
                } catch (EOFException e) {
                    info("Client #" + getClientThreadId() + " (" + getUser() + ") has disconnected from the server.");
                    running = false;
                    break;
                } catch (IOException | ClassNotFoundException e) {
                    error("Error when receiving a new message: " + e);
                    e.printStackTrace();
                    break;
                }
            }
            remove(getClientThreadId());
            close();
        }

        /**
         * Get the unique client thread ID for this server
         * @return The unique client thread ID for this server
         */
        public int getClientThreadId() {
            return ctid;
        }

        /**
         * Get the user that is connected to this client thread
         * @return The user that is connected to this client thread
         */
        public String getUser() {
            return user;
        }

        /**
         * Close the client thread
         */
        public void close() {
            try {
                sInput.close();
            } catch (Exception e) {
            }
            try {
                sOutput.close();
            } catch (Exception e) {
            }
            try {
                tlsServerProtocol.close();
            } catch (Exception e) {
            }
            try {
                socket.close();
            } catch (Exception e) {
            }
        }

        /**
         * Send a message to the client
         * @param message The message to send
         * @return Whether the message is sent successfully
         */
        public boolean writeMsg(ChatMessage message) {
            // Check if the server is shut down
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

    /**
     * Update the credentials file
     * @return Whether the update was successful.
     * @throws IOException When the write process fails
     */
    private boolean updateCredentialsFile() throws IOException {
        List<String> out = new ArrayList<>();
        for (String k: users.keySet()) {
            out.add(k + ":" + users.get(k));
        }
        // Just override everything.
        Files.write(credentials.toPath(), out, Charset.forName("UTF-8"));
        return true;
    }

    /**
     * Hashes a password with PBKDF2. Salt is required to hash the password.
     *
     * @param password The password to hash
     * @param salt The salt to make it random
     * @param iterations Amount of rounds to run the algorithm
     * @param keyLength The length of the key it will generate
     * @return The hashed password from the algorithm.
     */
    public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();
            return res;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {

        // Initialize all the options that are available
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
