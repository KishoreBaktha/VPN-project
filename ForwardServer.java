/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.lang.AssertionError;
import java.lang.Integer;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.StringTokenizer;

public class ForwardServer {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private static CryptCertificate serverCertificate;
    private static CryptCertificate caCertificate;

    private static SessionDecrypter sessionDecrypter;
    private static SessionEncrypter sessionEncrypter;

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() {

        try {

            Socket clientSocket = handshakeSocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            Logger.log("Incoming handshake connection from " + clientHostPort);

            /* This is where the handshake should take place */

            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.recv(clientSocket);

            if (!clientHello.getParameter("MessageType").equals("ClientHello")) {
                throw new Exception("Received unexpected message");
            }

            CryptCertificate clientCertificate = new CryptCertificate(clientHello.getParameter("Certificate"));

            clientCertificate.getCertificate().verify(caCertificate.getCertificate().getPublicKey());
            clientCertificate.getCertificate().checkValidity();

            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", serverCertificate.encodeCertificate());

            serverHello.send(clientSocket);

            HandshakeMessage forwardMessage = new HandshakeMessage();
            forwardMessage.recv(clientSocket);

            if (!forwardMessage.getParameter("MessageType").equals("Forward")) {
                throw new Exception("Received unexpected message");
            }
            targetHost = forwardMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));

            sessionEncrypter = new SessionEncrypter(128);
            byte[] sessionKeyBytes = sessionEncrypter.getKeyBytes();
            byte[] encryptedKey = HandshakeCrypto.encrypt(sessionKeyBytes, clientCertificate.getCertificate().getPublicKey());

            byte[] sessionIVBytes = sessionEncrypter.getIVBytes();
            byte[] encryptedIV = HandshakeCrypto.encrypt(sessionIVBytes, clientCertificate.getCertificate().getPublicKey());

            String sessionHost = InetAddress.getLocalHost().getHostAddress();

            listenSocket = new ServerSocket();
            listenSocket.bind(new InetSocketAddress(sessionHost, 0));

            HandshakeMessage sessionMessage = new HandshakeMessage();
            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", HandshakeCrypto.byte64Encode(encryptedKey));
            sessionMessage.putParameter("SessionIV", HandshakeCrypto.byte64Encode(encryptedIV));
            sessionMessage.putParameter("SessionHost", sessionHost);
            sessionMessage.putParameter("SessionPort", Integer.toString(listenSocket.getLocalPort()));

            sessionMessage.send(clientSocket);

            sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(), sessionEncrypter.encodeIV());

            Logger.log("Handshake over");

            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        /*
         * Fake the handshake result with static parameters.
         */

        /* listenSocket is a new socket where the ForwardServer waits for the
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort).
         * (This may give "Address already in use" errors, but that's OK for now.)
         */

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
//        targetHost = Handshake.targetHost;
//        targetPort = Handshake.targetPort;
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer() throws Exception {
    //throws IOException

        serverCertificate = new CryptCertificate(true, arguments.get("usercert"));
        caCertificate = new CryptCertificate(true, arguments.get("cacert"));

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while (true) {
            ForwardServerClientThread forwardThread;

            doHandshake();

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort,sessionDecrypter,sessionEncrypter);
            forwardThread.start();
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
            throws Exception {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }

}
