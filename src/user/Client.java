package user;

import java.io.IOException;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import other.CryptographicFunctions;
import other.Envelope;

public abstract class Client {

    PublicKey publicKey;

    protected SecretKey symmetricKey;
    protected SecretKey authenticationKey;
    protected IvParameterSpec nextIv;
    protected IvParameterSpec nextIvAuth;
    int message_number = 0;

    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;

    public boolean connect(final String server, final int port, PublicKey publicKey) {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Attempting to connect to server");

        try {
            // Connect to the specified server
            sock = new Socket(server, port);
            System.out.println("Connected to " + server + ":" + port);

            // Set up I/O streams with the server
            output = new ObjectOutputStream(sock.getOutputStream());
            input = new ObjectInputStream(sock.getInputStream());

            solveChallenge();

            //get the public key from the user
            this.publicKey = publicKey;
            // Connection is successful if we could initialize encrypted session
            return sendInitMessage(publicKey);

        } catch (Exception ex) {
            System.out.printf("\nWas not able to connect with server due to following error:\n%s\n", ex.getLocalizedMessage());
            return false;
        }

    }

    private void solveChallenge() throws IOException, ClassNotFoundException {
        Envelope challengeMsg = (Envelope) input.readObject();
        List<Object> objects = challengeMsg.getObjContents();
        if (challengeMsg.getMessage().equals("CHALLENGE")
                && objects != null && objects.size() == 3
                && objects.get(0) instanceof byte[]
                && objects.get(1) instanceof byte[]
                && objects.get(2) instanceof Integer) {

            byte[] challenge = (byte[]) objects.get(0);
            byte[] salt = (byte[]) objects.get(1);
            Integer size = (Integer) objects.get(2);

            byte[] hash = CryptographicFunctions.bruteForceHash(challenge, salt, size);

            Envelope solution = new Envelope("RESPONSE");
            solution.addObject(hash);
            output.writeObject(solution);
        }
    }

    private boolean sendInitMessage(PublicKey publicKey) throws GeneralSecurityException {
        Cipher rsaEncryptionCipher = CryptographicFunctions.createEncryptionCipher(publicKey);
        symmetricKey = CryptographicFunctions.generateAESKey();
        authenticationKey = CryptographicFunctions.generateAESKey();
        message_number++;
        return sendMessage("INITIALIZE", new Object[]{symmetricKey, authenticationKey}, rsaEncryptionCipher);
    }

    public boolean isConnected() {
        return !(sock == null || !sock.isConnected());
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
            } catch (IOException e) {
                System.err.println("Error: " + e.getMessage());
                //e.printStackTrace(System.err);
            }
        }
    }

    private boolean sendMessage(String operation, Object[] args, Cipher ciper) {
        try {
            Envelope message, response;
            //Tell the server to remove a user from the group
            message = new Envelope(operation);
            for (Object elem : args) {
                message.addObject(elem);
            }
            output.writeObject(Envelope.encryptEnvelope(message, ciper));

            response = decryptResponse((Envelope) input.readObject());
            System.out.println(response.getMessage());
            //If server indicates success, return true
            if (response.getMessage().equals("OK")) {
                return true;
            }
        } catch (Exception e) {
            System.out.printf("Could not complete operation: %s\n\n", e.getLocalizedMessage());
        }
        return false;
    }

    private boolean sendMessage(String operation, Object[] args, Cipher ciper, Cipher authCipher) {
        try {
            Envelope message, response;
            //Tell the server to remove a user from the group
            message = new Envelope(operation);
            for (Object elem : args) {
                message.addObject(elem);
            }
            output.writeObject(Envelope.encryptEnvelope(message, ciper, authCipher, message_number));
            message_number++;

            response = decryptResponse((Envelope) input.readObject());
            System.out.println(response.getMessage());
            //If server indicates success, return true
            if (response.getMessage().equals("OK")) {
                return true;
            }
        } catch (Exception e) {
            System.out.printf("Could not complete operation: %s\n\n", e.getLocalizedMessage());
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private <E> ArrayList<E> sendMessageList(String operation, Object[] args, Cipher ciper, Cipher authCipher) {
        try {
            Envelope message, response;
            message = new Envelope(operation);
            for (Object elem : args) {
                message.addObject(elem);
            }
            output.writeObject(Envelope.encryptEnvelope(message, ciper, authCipher, message_number));
            message_number++;

            response = decryptResponse((Envelope) input.readObject());
            //If server indicates success, return true
            if (response.getMessage().equals("OK")) {
                return (ArrayList<E>) response.getObjContents();
            }

        } catch (Exception e) {
            System.out.printf("Could not complete operation: %s\n\n", e.getLocalizedMessage());
        }
        return null;
    }

    private <E> ArrayList<E> sendMessageList(String operation, Object[] args, Cipher ciper) {
        try {
            Envelope message, response;
            message = new Envelope(operation);
            for (Object elem : args) {
                message.addObject(elem);
            }
            output.writeObject(Envelope.encryptEnvelope(message, ciper));

            response = decryptResponse((Envelope) input.readObject());
            //If server indicates success, return true
            if (response.getMessage().equals("OK")) {
                return (ArrayList<E>) response.getObjContents();
            }

        } catch (Exception e) {
            System.out.printf("Could not complete operation: %s\n\n", e.getLocalizedMessage());
        }
        return null;
    }

    private <E> E sendMessageObject(String operation, Object[] args, Cipher ciper, Cipher auth) {
        ArrayList<E> list = this.<E>sendMessageList(operation, args, ciper, auth);
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.get(0);
    }

    protected boolean sendMessage(String operation, Object[] args) {
        try {
            return sendMessage(operation, args, encryptionCipher(), authenticationCipher());
        } catch (GeneralSecurityException ex) {
            System.out.println(ex);
            return false;
        }
    }

    protected <E> ArrayList<E> sendMessageList(String operation, Object[] args) {
        try {
            return sendMessageList(operation, args, encryptionCipher(), authenticationCipher());
        } catch (GeneralSecurityException ex) {
            System.out.println(ex);
            return null;
        }
    }

    protected <E> E sendMessageObject(String operation, Object[] args) {
        try {
            return sendMessageObject(operation, args, encryptionCipher(), authenticationCipher());
        } catch (GeneralSecurityException ex) {
            System.out.println(ex);
            return null;
        }
    }

    private Cipher encryptionCipher() throws GeneralSecurityException {
        return CryptographicFunctions.createEncryptionCipher(symmetricKey, nextIv);
    }

    private Cipher authenticationCipher() throws GeneralSecurityException {
        return CryptographicFunctions.createEncryptionCipher(authenticationKey, nextIvAuth);
    }

    private Envelope decryptResponse(Envelope response) throws GeneralSecurityException {
        if (!verifyMessageContents(response.getObjContents())) {
            return new Envelope("Decryption Failure!");
        }
        @SuppressWarnings("unchecked")
        byte[] arr1 = (byte[]) response.getObjContents().get(2);
        @SuppressWarnings("unchecked")
        byte[] arr2 = (byte[]) response.getObjContents().get(3);
        @SuppressWarnings("unchecked")
        byte[] arr3 = (byte[]) response.getObjContents().get(4);
        @SuppressWarnings("unchecked")
        byte[] arr4 = (byte[]) response.getObjContents().get(5);

        IvParameterSpec iv = new IvParameterSpec(arr1);
        nextIv = new IvParameterSpec(arr2);
        IvParameterSpec ivAuth = new IvParameterSpec(arr3);
        nextIvAuth = new IvParameterSpec(arr4);

        Cipher decryptionCipher, authenticationCipher;
        decryptionCipher = CryptographicFunctions.createDecryptionCipher(symmetricKey, iv);
        authenticationCipher = CryptographicFunctions.createEncryptionCipher(authenticationKey, ivAuth);

        return Envelope.decryptEnvelope(response, decryptionCipher, authenticationCipher, message_number);
    }

    private boolean verifyMessageContents(ArrayList<Object> objects) {
        if (objects == null || objects.size() != 6) {
            return false;
        }
        for (int i = 0; i < 5; i++) {
            Object elem = objects.get(i);
            if (elem == null || !(elem instanceof byte[])) {
                System.out.printf("\t%d: Expected object of type byte[], but got object of type %s!\n", i, (elem == null) ? null : elem.getClass());
                return false;
            }
        }
        return true;
    }
}
