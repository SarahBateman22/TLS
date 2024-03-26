package TLS;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;

public class Client {
    private byte[] nonce;
    private static Certificate clientCert;
    private PrivateKey rsaPrivKey;
    private static BigInteger dhPublicKey;
    private BigInteger dhPrivKey;
    private static byte[] dhSignedKey;
    private static ByteArrayOutputStream allMessages;

    public Client() throws Exception {
        String certPath = "../CertificatesAndKeyPairs/CASignedClientCertificate.pem";
        String rsaPath = "../CertificatesAndKeyPairs/clientPrivateKey.der";

        nonce = generateNonce();
        clientCert = helpers.loadCertificate(certPath);
        rsaPrivKey = helpers.getRSAPrivateKey(rsaPath);
        dhPrivKey = new BigInteger(Integer.toString(new SecureRandom().nextInt()));
        dhPublicKey = helpers.getDHPublicKey(dhPrivKey);
        dhSignedKey = helpers.getDHsignedKey(rsaPrivKey, dhPublicKey);
        allMessages = new ByteArrayOutputStream();
    }

    public void completeClientHandshake(ObjectInputStream inputStream, ObjectOutputStream outputStream) throws Exception {

        //Step 1: Send nonce
        nonce = generateNonce();
        outputStream.writeObject(nonce);
        allMessages.write(nonce);

        //Step 2: Receive server certificate, serverDHPub, and signed Diffie-Hellman public key AND VALIDATE
        BigInteger serverDHPub = helpers.validateAndReturnPublicKey(inputStream, allMessages);

        //Step 3: Send certificate, Diffie-Hellman public key, and signed DHPub to Server
        helpers.sendCertAndKeys(outputStream, clientCert, dhPublicKey, dhSignedKey);
        allMessages.write(clientCert.getEncoded());
        allMessages.write(dhPublicKey.toByteArray());
        allMessages.write(dhSignedKey);

        //Step 4: Generate shared DH secret key
        BigInteger sharedSecret = helpers.getSharedDHKey(dhPrivKey, serverDHPub);

        //Step 4.5: Generate secret keys with shared secret
        helpers.makeSecretKeys(nonce, sharedSecret.toByteArray());
        System.out.println("Client secret keys have been generated.");

        //Step 5: Receive summary message from server AND VALIDATE
        byte[] serverSummaryMsg = (byte[]) inputStream.readObject();

        if(helpers.verifyMessageHistory(serverSummaryMsg, allMessages.toByteArray(), helpers.serverMAC)){
            System.out.println("Message history matches with the server.");
        }
        else {
            throw new SecurityException("Message history does not match the server.");
        }

        //Step 6: Send HMAC of all handshake messages so far (including the previous step) using the client's MAC key
        byte[] summaryMsg = helpers.macMessage(allMessages.toByteArray(), helpers.clientMAC);
        outputStream.writeObject(summaryMsg);
        System.out.println("Sent summary message to server.");
    }

    public byte[] generateNonce(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private void sendAndReceiveTestMsgs(ObjectInputStream inputStream, ObjectOutputStream outputStream) throws Exception {
        byte[] testMsgReceived = (byte[]) inputStream.readObject();
        byte[] decryptedMsg = helpers.decrypt(testMsgReceived, helpers.serverEncrypt, helpers.serverIV, helpers.serverMAC);
        String plaintextMsg = new String(decryptedMsg, StandardCharsets.UTF_8);

        System.out.println("Encrypted message received: " + Arrays.toString(testMsgReceived));
        System.out.println("Plaintext message received: " + plaintextMsg);

        String secondMsg = "Hi Server! I am the client.";
        byte[] encryptedSecondMsg = helpers.encrypt(secondMsg.getBytes(), helpers.clientEncrypt, helpers.clientIV, helpers.clientMAC);
        System.out.println("Plaintext message to be sent: " + secondMsg);
        System.out.println("Encrypted message to be sent: " + Arrays.toString(encryptedSecondMsg));
        outputStream.writeObject(encryptedSecondMsg);
        outputStream.flush();
        System.out.println("Message sent to server.");
    }

    public static void main(String[] args) throws Exception {
        Client c = new Client();
        String serverAddress = "127.0.0.1";
        int serverPort = 8080;

        try {
            Socket socket = new Socket(serverAddress, serverPort);
            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
            c.completeClientHandshake(inputStream, outputStream);
            c.sendAndReceiveTestMsgs(inputStream, outputStream);
        }

        catch (Exception e) {
            System.out.println("TLS handshake failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
