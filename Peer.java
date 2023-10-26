import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

public class Peer {
    private final int port;
    private SecretKey secretKey;

    public Peer(int port) throws Exception {
        this.port = port;
        this.secretKey = MessageUtils.generateKey();
    }

    public void start() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Peer is running and waiting for connections on port " + port);
            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    handleClient(clientSocket);
                } catch (Exception e) {
                    System.err.println("Error handling client: " + e.getMessage());
                }
            }
        }
    }

    private void handleClient(Socket clientSocket) throws Exception {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            String encryptedMessage = in.readLine();
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            String decryptedMessage = MessageUtils.decryptMessage(encryptedBytes, secretKey);

            System.out.println("Received encrypted message: " + encryptedMessage);
            System.out.println("Decrypted message: " + decryptedMessage);

            // Send a response back
            String response = "Message received!";
            byte[] encryptedResponse = MessageUtils.encryptMessage(response, secretKey);
            String encryptedResponseStr = Base64.getEncoder().encodeToString(encryptedResponse);
            out.println(encryptedResponseStr);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java Peer <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);
        Peer peer = new Peer(port);
        peer.start();
    }
}
