package TLS;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class helpers {

    //session keys shared by server and client
    public static byte[] serverEncrypt;
    public static byte[] clientEncrypt;
    public static byte[] serverMAC;
    public static byte[] clientMAC;
    public static byte[] serverIV;
    public static byte[] clientIV;

    //2048-bit MODP Group from RFC 3526 Group 14
    private static final String hexPrime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
    private static final BigInteger N = new BigInteger(hexPrime, 16);
    private static final BigInteger g = BigInteger.valueOf(2);

    //helper function for server and client to load in the certificates
    public static X509Certificate loadCertificate(String certificatePath) throws Exception {
        FileInputStream file = new FileInputStream(certificatePath);
        //generating a certificate factory, X.509 is a standard format for public key certificates
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        //use the certificate factory to parse the info in the file and pull out the X509 cert
        X509Certificate cert = (X509Certificate) cf.generateCertificate(file);
        file.close();
        return cert;
    }

    public static BigInteger getDHPublicKey(BigInteger dhPrivKey) {
        //The public keys can be derived: serverDHPub = g^serverDHPriv mod N and clientDHPub = g^clientDHPriv mod N.
        return g.modPow(dhPrivKey, N);
    }

    public static byte[] getDHsignedKey(PrivateKey rsaPrivKey, BigInteger dhPublicKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(rsaPrivKey);
        signer.update(dhPublicKey.toByteArray());
        return signer.sign();
    }

    public static PrivateKey getRSAPrivateKey(String rsaPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream input = new FileInputStream(rsaPath);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input.readAllBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static boolean validate(Certificate certToValidate) throws Exception {
        String path = "../CertificatesAndKeyPairs/CAcertificate.pem";
        Certificate caCert = loadCertificate(path);
        try {
            PublicKey caPublicKey = caCert.getPublicKey();
            certToValidate.verify(caPublicKey);
            return true;
        }
        //if there's an exception then it wasn't able to be validated, return false
        catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static BigInteger validateAndReturnPublicKey(ObjectInputStream inputStream, ByteArrayOutputStream allMessages) throws Exception {
        //receive everything in
        Certificate certificate = (Certificate) inputStream.readObject();
        allMessages.write(certificate.getEncoded());
        BigInteger dhPublic = (BigInteger) inputStream.readObject();
        allMessages.write(dhPublic.toByteArray());
        byte[] signedDH = (byte[]) inputStream.readObject();
        allMessages.write(signedDH);
        System.out.println("Received handshake files.");

        //verify certificate and signature
        boolean isValid = helpers.validate(certificate);
        if (isValid) {
            System.out.println("Certificate validated!");
        }
        else {
            throw new SecurityException("Certificate is invalid.");
        }

        return dhPublic;
    }

    static void sendCertAndKeys(ObjectOutputStream outputStream, Certificate certificate, BigInteger publicKey, byte[] signedKey) throws IOException {
        outputStream.writeObject(certificate);
        outputStream.writeObject(publicKey);
        outputStream.writeObject(signedKey);
        System.out.println("Sent handshake files.");
        outputStream.flush();
    }

    public static BigInteger getSharedDHKey(BigInteger privateKey, BigInteger otherPublicKey) {
        return otherPublicKey.modPow(privateKey, N);
    }

    //HMAC-based Key Derivation Function
    public static byte[] hkdfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(input, "HmacSHA256");
        hmacSha256.init(keySpec);
        hmacSha256.update((tag + "\1").getBytes());
        byte[] okm = hmacSha256.doFinal();
        byte[] result = new byte[16];
        System.arraycopy(okm, 0, result, 0, result.length);
        return result;
    }

    public static void makeSecretKeys(byte[] clientNonce, byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk = hkdfExpand(sharedSecret, "masterKey" + new String(clientNonce, StandardCharsets.UTF_8));
        serverEncrypt = hkdfExpand(prk, "server encrypt");
        clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt");
        serverMAC = hkdfExpand(clientEncrypt, "server MAC");
        clientMAC = hkdfExpand(serverMAC, "client MAC");
        serverIV = hkdfExpand(clientMAC, "server IV");
        clientIV = hkdfExpand(serverIV, "client IV");
    }

    public static byte[] macMessage(byte[] message, byte[] macKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(macKey, "HmacSHA256");
        HMAC.init(secretKeySpec);
        HMAC.update(message);
        return HMAC.doFinal();
    }

    public static boolean verifyMessageHistory(byte[] otherHostMacMsg, byte[] thisHostMsg, byte[] macKey) throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        byte[] thisHostMacMsg = helpers.macMessage(thisHostMsg, macKey);
        return Arrays.equals(thisHostMacMsg, otherHostMacMsg);
    }

    public static byte[] encrypt(byte[] plainText, byte[] encryptionKey, byte[] iv, byte[] macKey) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        //Compute the HMAC of the message using the appropriate MAC key
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA256");
        mac.init(macKeySpec);
        byte[] hmac = mac.doFinal(plainText);

        //concatenate the mac with the plaintext
        outputStream.write(plainText);
        outputStream.write(hmac);
        byte[] plainTextWithHmac = outputStream.toByteArray();

        //Use the cipher object to encrypt the message data concatenated with the MAC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(plainTextWithHmac);
    }

    public static byte[] decrypt(byte[] cipherText, byte[] decryptionKey, byte[] iv, byte[] macKey) throws Exception {
        //decrypt the whole message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(decryptionKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedData = cipher.doFinal(cipherText);

        //separate the message and the mac from each other
        byte[] originalMessage = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - 32);
        byte[] messageHmac = Arrays.copyOfRange(decryptedData, decryptedData.length - 32, decryptedData.length);

        //redo the computing mac steps to verify with the one in the message
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA256");
        mac.init(macKeySpec);
        byte[] computedHmac = mac.doFinal(originalMessage);

        //check that they're equal
        if (Arrays.equals(messageHmac, computedHmac)) {
            System.out.println("Macs match!");
        }
        else{
            throw new SecurityException("MAC verification failed");
        }
        return originalMessage;
    }

}
