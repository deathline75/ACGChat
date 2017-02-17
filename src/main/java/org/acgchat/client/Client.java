package org.acgchat.client;

import org.acgchat.common.ChatMessage;
import org.acgchat.common.Logger;
import org.apache.commons.cli.*;
import org.bouncycastle.crypto.tls.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * The command-line interface and logic of the client.
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class Client extends Logger {

    private String server;
    private int port;
    private X509Certificate caCertificate;
    private Socket socket;
    private TlsClientProtocol tlsClientProtocol;
    private ObjectInputStream sInput;
    private ObjectOutputStream sOutput;
    private boolean login;
    private String username;
    private String password;
    public static final String regexPassword = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[!@#$%^&*'\":;,./<>?|`~+=]).{8,}$";

    /**
     * The client that will handle the connection
     * @param server The server's IP or host name
     * @param port The server's port number
     * @param cacert The location of the root CA's certificate
     * @param login Determines if the connection starts as a login (true) or a register (false)
     * @param username The username to conenct as
     * @param password The password to authenticate as
     * @throws CertificateException When the certificate given is invalid
     * @throws IOException When the file has issues loading
     * @throws NoSuchAlgorithmException When the algorithm for the certificate does not exist
     */
    Client(String server, int port, String cacert, boolean login, String username, String password) throws CertificateException, IOException, NoSuchAlgorithmException {
        info("Client will connect to: " + server + ":" + port);
        this.server = server;
        this.port = port;
        this.login = login;
        this.username = username;
        this.password = password;
        info("Loading in certificate authority's certificate...");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(cacert);
        caCertificate = (X509Certificate) factory.generateCertificate(fis);
        fis.close();
        info("Load completed.");

    }

    /**
     * Start the connection between the client and server
     * @return Whether the connection to the server was successful.
     */
    public boolean start() {
        Security.addProvider(new BouncyCastleProvider());
        info("Connecting to the server...");
        try {
            socket = new Socket(server, port);
            // Create a new BouncyCastle's implementation of TLS client protocol
            tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
            // Initialise the TLS connection
            tlsClientProtocol.connect(new DefaultTlsClient() {

                public TlsAuthentication getAuthentication() throws IOException {
                    return new ServerOnlyTlsAuthentication() {
                        public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
                            try {
                                X509Certificate serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(serverCertificate.getCertificateList()[0].getEncoded()));
                                verifyCertificates(caCertificate, serverCert);
                            } catch (CertificateException e) {
                                error("Unable to verify server's certificate: " + e);
                                e.printStackTrace();
                            }
                        }
                    };
                }
            });
            /*
             * Get the TLS connection's socket stream to use, as all traffic using this stream will be encrypted
             * and decrypted automatically.
             */
            sOutput = new ObjectOutputStream(tlsClientProtocol.getOutputStream());
            sOutput.flush();
            sInput = new ObjectInputStream(tlsClientProtocol.getInputStream());

            // Sends the first authentication packet based on login boolean.
            if (login) {
                info("Logging you into the server...");
                sOutput.writeObject(new ChatMessage(ChatMessage.ChatMessageType.LOGIN, username, password));
            } else {
                info("Registering you into the server...");
                sOutput.writeObject(new ChatMessage(ChatMessage.ChatMessageType.REGISTER, username, password));
            }

            // Checks if the login was successful.
            ChatMessage reply = (ChatMessage) sInput.readObject();
            switch (reply.getType()) {
                case SUCCESS:
                    info((String) reply.getMessage());
                    break;
                default:
                    error("Unable to register/login: " + reply.getMessage());
                    return false;
            }

        } catch (IOException | ClassNotFoundException e) {
            error("Unable to connect to server: " + e);
            e.printStackTrace();
            return false;
        }
        info("Connection complete. Listening from server.");
        new ListenFromServer().start();
        return true;
    }

    /**
     * Send a message to the server
     * @param chatMessage The message to send
     */
    protected void sendMessage(ChatMessage chatMessage) {
        try {
            sOutput.writeObject(chatMessage);
        } catch (IOException e) {
            error("Exception writing to server: " + e);
            e.printStackTrace();
        }
    }

    /**
     * Disconnect the client completely off the server.
     */
    protected void disconnect() {
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

        // Initialize all the arguments the client can use
        Option serverAddressOption = Option.builder("a").argName("address").longOpt("server-address").hasArg().desc("server address to connect to").build();
        Option serverPortOption = Option.builder("p").argName("number").longOpt("server-port").hasArg().desc("port number to connect to").build();
        Option loginOption = Option.builder("l").longOpt("login").build();
        Option registerOption = Option.builder("r").longOpt("register").build();
        Option usernameOption = Option.builder("u").argName("username").longOpt("username").hasArg().desc("username to connect as").build();
        Option passwordOption = Option.builder("up").argName("password").longOpt("password").hasArg().desc("password to authenticate the user").build();
        Option caCertOption = Option.builder("c").argName("file").longOpt("certificate").hasArg().desc("certificate authority's certificate").build();

        // Add all the options into options.
        Options options = new Options();
        options.addOption(serverAddressOption);
        options.addOption(serverPortOption);
        options.addOption(loginOption);
        options.addOption(registerOption);
        options.addOption(usernameOption);
        options.addOption(passwordOption);
        options.addOption(caCertOption);

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
            formatter.printHelp("Client", options);

            System.exit(1);
            return;
        }

        /*// default values
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
        }*/

        // Assume the user is attempting to login unless stated otherwise
        boolean login = true;
        // wait for messages from user
        Scanner scan = new Scanner(System.in);

        if (cmd.hasOption("login")) {
            login = true;
        } else if (cmd.hasOption("register")) {
            login = false;
        } else {
            System.out.print("Are you logging in or registering? [L/r]: ");
            String input = scan.nextLine();
            if (input.startsWith("r")) {
                login = false;
            }
        }

        String userName = cmd.getOptionValue("username");
        // Ask for username if not specified in initial command
        while (userName == null || userName.isEmpty()) {
            System.out.print("Enter your username: ");
            userName = scan.nextLine();
        }

        // Ask for password if not specified in initial command
        String password = cmd.getOptionValue("password");
        while (password == null) {
            System.out.print("Enter your password: ");
            password = scan.nextLine();

            // Check password complexity through regex
            if(!password.matches(regexPassword)){
               System.out.println("Password requires a combination of letters, digit and a special character");
                password = null;
            }
            // Check if we're logged in, if we're not logged in then..
            else if (!login) {
                System.out.print("Re-enter your password: ");
                if (!scan.nextLine().equals(password)) {
                    password = null;
                    System.out.println("Passwords do not match!");
                }
            }
        }

        // create the Client object
        Client client = null;
        try {
            // If the port number given is invalid, just set it to 1500
            int port = Integer.parseInt(cmd.getOptionValue("server-port", "1500"));
            client = new Client(cmd.getOptionValue("server-address", "localhost"),
                    port,
                    cmd.getOptionValue("certificate", "ACGChatCA.cert"),
                    login, userName, password);
        } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // test if we can start the connection to the Server
        // if it failed nothing we can do
        if (!client.start())
            return;

        // loop forever for message from the user
        while (true) {
            System.out.print("> ");
            // read message from user
            String msg = scan.nextLine();

            if (client.socket.isClosed())
                break;

            // logout if message is LOGOUT
            if (msg.equalsIgnoreCase("/logout")) {
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.LOGOUT, userName, null));
                // break to do the disconnect
                break;
            }
            // message WhoIsIn
            else if (msg.startsWith("/")) {
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, userName, msg.substring(1)));
            } else {                // default to ordinary message
                client.sendMessage(new ChatMessage(ChatMessage.ChatMessageType.MESSAGE, userName, msg));
            }
        }
        // done disconnect
        client.disconnect();
    }

    /**
     * Verifies the certificate being sent over from the server.
     * @param CACert The root CA's certificate to check against
     * @param serverCert The server certificate to check with the root CA
     * @throws CertificateException When the certificate does not meet requirements.
     */
    private static void verifyCertificates(X509Certificate CACert, X509Certificate serverCert) throws CertificateException {
        if (CACert == null || serverCert == null) {
            throw new IllegalArgumentException("Certificate not found");
        }

        // Check if the server certificate is signed by the CA certificate
        if (!CACert.equals(serverCert)) {
            try {
                serverCert.verify(CACert.getPublicKey());
            } catch (Exception e) {
                throw new CertificateException("Certificate not trusted", e);
            }
        }

        // Check if expired
        try {
            serverCert.checkValidity();
        } catch (Exception e) {
            throw new CertificateException("Certificate not trusted. It has expired", e);
        }
    }

    /**
    * a class that waits for the message from the server and append them to the respective print locations.
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
                    disconnect();
                    warning("Press 'Enter' to quit.");
                    break;
                }
                // can't happen with a String object but need the catch anyhow
                catch (ClassNotFoundException e2) {
                }
            }
        }
    }

}
