// Server Code: SecureChatServer.java

import java.io.*;
import java.net.*;
import java.util.*;

public class SecureChatServer {
    private static final int PORT = 5000;
    private static final List<ClientHandler> clients = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Secure Chat Server started on port " + PORT);
    
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("New client connected.");
            ClientHandler handler = new ClientHandler(clientSocket);
            clients.add(handler);
            new Thread(handler).start();
        }
    }
    
    static class ClientHandler implements Runnable {
        private Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
    
        public ClientHandler(Socket socket) {
            this.socket = socket;
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    
        public void run() {
            try {
                while (true) {
                    Object obj = in.readObject();
                    if (obj instanceof String) {
                        String str = (String) obj;
                        broadcast(str);
                    }
                }
            } catch (Exception e) {
                System.out.println("Client disconnected.");
            } finally {
                try {
                    clients.remove(this);
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    
        private void broadcast(String msg) throws IOException {
            synchronized (clients) {
                for (ClientHandler client : clients) {
                    if (client != this) {
                        client.out.writeObject(msg);
                        client.out.flush();
                    }
                }
            }
        }
    }
    
}
