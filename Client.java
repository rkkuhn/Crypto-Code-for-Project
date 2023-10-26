import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

public class Client {
    private final String hostname;
    private final int port;
    private SecretKey secretKey;

    public Client(String hostname, int port) throws Exception {
        this.hostname = hostname;
        this.port = port;
        this.secretKey = MessageUtils.generateKey();
    }

    public void start() throws IOException {
        try (Socket socket = new Socket(hostname, port);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            // Send an encrypted message
            String message = "Hello from client!";
            byte[] encryptedMessage = MessageUtils.encryptMessage(message, secretKey);
            String encryptedMessageStr = Base64.getEncoder().encodeToString(encryptedMessage);
            out.println(encryptedMessageStr);

            // Receive and decrypt the response
            String encryptedResponse = in.readLine();
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedResponse);
            String decryptedResponse = MessageUtils.decryptMessage(encryptedBytes, secretKey);
            System.out.println("Received encrypted response: " + encryptedResponse);
            System.out.println("Decrypted response: " + decryptedResponse);

        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java Client <hostname> <port>");
            System.exit(1);
        }

        String hostname = args[0];
        int port = Integer.parseInt(args[1]);
        Client client = new Client(hostname, port);
        client.start();
    }
}
