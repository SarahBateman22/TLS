package TLS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;

public class Server {
    private static Certificate serverCert;
    private PrivateKey rsaPrivKey;
    private static BigInteger dhPublicKey;
    private static BigInteger dhPrivKey;
    private static byte[] dhSignedKey;
    private static ByteArrayOutputStream allMessages;

    public Server() throws Exception {
        String certPath = "../CertificatesAndKeyPairs/CASignedServerCertificate.pem";
        String rsaPath = "../CertificatesAndKeyPairs/serverPrivateKey.der";

        //BOTH NEED TO HAVE:
        //signed certificate
        serverCert = helpers.loadCertificate(certPath);

        //diffie helmen private key
        dhPrivKey = new BigInteger(Integer.toString(new SecureRandom().nextInt()));

        //diffie helmen public key
        dhPublicKey = helpers.getDHPublicKey(dhPrivKey);

        //rsa private key
        rsaPrivKey = helpers.getRSAPrivateKey(rsaPath);

        //diffie helmen shared key
        dhSignedKey = helpers.getDHsignedKey(rsaPrivKey, dhPublicKey);

        //history of all messages sent and received
        allMessages = new ByteArrayOutputStream();
    }

    public void runServer() throws IOException {
        int serverPort = 8080;
        try (ServerSocket serverSocket = new ServerSocket(serverPort)) {
            System.out.println("Server listening on port " + serverPort);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("Client connected!");
                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                completeServerHandshake(inputStream, outputStream);
                sendAndReceiveTestMsgs(inputStream, outputStream);
            }
        }
        catch (Exception e) {
            System.out.println("Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void completeServerHandshake(ObjectInputStream inputStream, ObjectOutputStream outputStream) throws Exception {
        //Step 1: Receive nonce from client
        byte[] clientNonce = (byte[]) inputStream.readObject();
        System.out.println("Received nonce from client!");
        allMessages.write(clientNonce);

        //Step 2: Send server's certificate, serverDHPub, and signed Diffie-Hellman public key
        helpers.sendCertAndKeys(outputStream, serverCert, dhPublicKey, dhSignedKey);
        allMessages.write(serverCert.getEncoded());
        allMessages.write(dhPublicKey.toByteArray());
        allMessages.write(dhSignedKey);

        //Step 3: Receive info from client AND VALIDATE
        BigInteger clientDHPub = helpers.validateAndReturnPublicKey(inputStream, allMessages);
        assert(clientDHPub != null);

        //Step 4: Generate shared DH secret key
        BigInteger sharedSecret = helpers.getSharedDHKey(dhPrivKey, clientDHPub);

        //Step 4.5: Generate secret keys with shared secret
        helpers.makeSecretKeys(clientNonce, sharedSecret.toByteArray());
        System.out.println("Server secret keys have been generated.");

        //Step 5: Send HMAC of all handshake messages so far using the server's MAC key
        byte[] summaryMsg = helpers.macMessage(allMessages.toByteArray(), helpers.serverMAC);
        outputStream.writeObject(summaryMsg);
        System.out.println("Sent summary message to client.");

        //Step 6: Receive summary message from client AND VALIDATE
        byte[] clientSummaryMsg = (byte[]) inputStream.readObject();

        if(helpers.verifyMessageHistory(clientSummaryMsg, allMessages.toByteArray(), helpers.clientMAC)){
            System.out.println("Message history matches with the client.");
        }
        else {
            throw new SecurityException("Message history does not match the client.");
        }

    }

    private void sendAndReceiveTestMsgs(ObjectInputStream inputStream, ObjectOutputStream outputStream) throws Exception {
        String firstMsg = "Sending a test message to the client...";
        byte[] encryptedFirstMsg = helpers.encrypt(firstMsg.getBytes(), helpers.serverEncrypt, helpers.serverIV, helpers.serverMAC);
        System.out.println("Plaintext message to be sent: " + firstMsg);
        System.out.println("Encrypted message to be sent: " + Arrays.toString(encryptedFirstMsg));
        outputStream.writeObject(encryptedFirstMsg);
        outputStream.flush();
        System.out.println("Message sent to client.");

        byte[] testMsgReceived = (byte[]) inputStream.readObject();
        byte[] decryptedMsg = helpers.decrypt(testMsgReceived, helpers.clientEncrypt, helpers.clientIV, helpers.clientMAC);
        String plaintextMsg = new String(decryptedMsg, StandardCharsets.UTF_8);

        System.out.println("Encrypted message received: " + Arrays.toString(testMsgReceived));
        System.out.println("Plaintext message received: " + plaintextMsg);
    }

    public static void main(String[] args) throws Exception {
        Server s = new Server();
        try {
            s.runServer();
        } catch (IOException e) {
            System.out.println("Failed to start server: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
