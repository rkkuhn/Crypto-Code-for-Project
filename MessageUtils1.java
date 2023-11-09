import java.util.Base64;

public class MessageUtils {
    private static final int CAESAR_SHIFT = 3; // You can choose a different shift value

    public static String encryptMessage(String message, SecretKey secretKey) {
        // Convert the message to a char array for encryption
        char[] messageChars = message.toCharArray();

        // Apply Caesar cipher encryption
        for (int i = 0; i < messageChars.length; i++) {
            char originalChar = messageChars[i];
            if (Character.isLetter(originalChar)) {
                char encryptedChar = encryptChar(originalChar, CAESAR_SHIFT);
                messageChars[i] = encryptedChar;
            }
        }

        // Convert the encrypted char array to a string
        return new String(messageChars);
    }

    public static String decryptMessage(String encryptedMessage, SecretKey secretKey) {
        // Convert the encrypted message to a char array for decryption
        char[] encryptedChars = encryptedMessage.toCharArray();

        // Apply Caesar cipher decryption
        for (int i = 0; i < encryptedChars.length; i++) {
            char encryptedChar = encryptedChars[i];
            if (Character.isLetter(encryptedChar)) {
                char decryptedChar = decryptChar(encryptedChar, CAESAR_SHIFT);
                encryptedChars[i] = decryptedChar;
            }
        }

        // Convert the decrypted char array to a string
        return new String(encryptedChars);
    }

    private static char encryptChar(char ch, int shift) {
        // Encrypt a single character using Caesar cipher
        char base = Character.isLowerCase(ch) ? 'a' : 'A';
        return (char) (((ch - base + shift) % 26 + 26) % 26 + base);
    }

    private static char decryptChar(char ch, int shift) {
        // Decrypt a single character using Caesar cipher
        char base = Character.isLowerCase(ch) ? 'a' : 'A';
        return (char) (((ch - base - shift) % 26 + 26) % 26 + base);
    }
}

In this modified version, the encryptMessage and decryptMessage methods now use a simple Caesar cipher to perform encryption and decryption. The CAESAR_SHIFT constant represents the shift value in the Caesar cipher, and you can adjust it based on your preference.
