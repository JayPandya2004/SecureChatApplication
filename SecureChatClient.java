// Client Code: SecureChatClient.java

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecureChatClient {
    private JTextArea chatArea;
    private JTextField inputField;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private SecretKey aesKey;
    private PublicKey otherPublicKey;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SecureChatClient(String host, int port) {
        JFrame frame = new JFrame("Secure Chat Client");
        frame.setSize(400, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);

        inputField = new JTextField();
        inputField.setEnabled(false);
        inputField.addActionListener(e -> sendMessage());

        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(inputField, BorderLayout.SOUTH);
        frame.setVisible(true);

        try {
            Socket socket = new Socket(host, port);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            generateRSAKeys();
            sendPublicKey();

            new Thread(() -> listenForMessages()).start();

        } catch (Exception e) {
            chatArea.append("Error: " + e.getMessage());
        }
    }

    private void listenForMessages() {
        try {
            while (true) {
                Object obj = in.readObject();
                if (obj instanceof String) {
                    String str = (String) obj;
                    if (str.startsWith("RSA:")) {
                        receivePublicKey(str.substring(4));
                        sendEncryptedAESKey();
                    } else if (str.startsWith("AES:")) {
                        receiveEncryptedAESKey(str.substring(4));
                    } else if (aesKey != null) {
                        String msg = decryptAES(str);
                        chatArea.append("Friend: " + msg + "\n");
                    }
                }
            }
        } catch (Exception e) {
            chatArea.append("Connection closed.\n");
        }
    }

    private void sendMessage() {
        try {
            if (aesKey == null) {
                chatArea.append("[Key exchange not completed. Wait...]\n");
                return;
            }
            String msg = inputField.getText();
            inputField.setText("");
            String encrypted = encryptAES(msg);
            out.writeObject(encrypted);
            out.flush();
            chatArea.append("Me: " + msg + "\n");
        } catch (Exception e) {
            chatArea.append("[Send Error]\n");
        }
    }

    private void generateRSAKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    private void sendPublicKey() throws IOException {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        out.writeObject("RSA:" + encoded);
        out.flush();
    }

    private void receivePublicKey(String base64) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        otherPublicKey = kf.generatePublic(spec);
        chatArea.append("[Public key received]\n");
    }

    private void sendEncryptedAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        aesKey = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, otherPublicKey);
        byte[] encrypted = cipher.doFinal(aesKey.getEncoded());
        String base64 = Base64.getEncoder().encodeToString(encrypted);
        out.writeObject("AES:" + base64);
        out.flush();
        inputField.setEnabled(true);
    }

    private void receiveEncryptedAESKey(String base64) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(base64);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = cipher.doFinal(encrypted);
        aesKey = new SecretKeySpec(decoded, "AES");
        chatArea.append("[AES key received]\n");
        inputField.setEnabled(true);
    }

    private String encryptAES(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptAES(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureChatClient("localhost", 5000));
    }
}
