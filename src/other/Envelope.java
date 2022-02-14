package other;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.util.ArrayList;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import javax.crypto.spec.SecretKeySpec;
import java.security.Signature;
import java.nio.*;

public class Envelope implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7726335089122193103L;
    private String msg;
    private ArrayList<Object> objContents = new ArrayList<>();

    public Envelope(String text) {
        msg = text;
    }

    public String getMessage() {
        return msg;
    }

    public ArrayList<Object> getObjContents() {
        return objContents;
    }

    public void addObject(Object object) {
        objContents.add(object);
    }

    public static Envelope encryptEnvelope(Envelope envelope, Cipher cipher, Cipher authenticationCipher, int message_number) {
        try {
            envelope.addObject(message_number);
            int AUTHENTICATION_SIZE = 8;
            ByteArrayOutputStream envelopeToByte = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(envelopeToByte);
            oos.writeObject(envelope);
            oos.flush();
            byte[] encryptedEnvelope = envelopeToByte.toByteArray();
            byte[] number_as_bytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(message_number).array();
            byte[] authEnvelope = authenticationCipher.doFinal(encryptedEnvelope);
            encryptedEnvelope = cipher.doFinal(encryptedEnvelope);
            byte[] residue = new byte[AUTHENTICATION_SIZE];
            for (int i = 0; i < AUTHENTICATION_SIZE; i++) {
                residue[i] = authEnvelope[authEnvelope.length - AUTHENTICATION_SIZE + i];
            }
            envelope = new Envelope("ENCRYPTED");
            envelope.addObject(encryptedEnvelope);
            envelope.addObject(residue);
            return envelope;

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("WARNING: UNENCRYPTED ENVELOPE");
        }
        return null;
    }

    public static Envelope encryptEnvelope(Envelope envelope, Cipher cipher) {
        try {
            ByteArrayOutputStream envelopeToByte = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(envelopeToByte);
            oos.writeObject(envelope);
            oos.flush();
            byte[] encryptedEnvelope = envelopeToByte.toByteArray();
            encryptedEnvelope = cipher.doFinal(encryptedEnvelope);
            envelope = new Envelope("ENCRYPTED");
            envelope.addObject(encryptedEnvelope);
            return envelope;

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("WARNING: UNENCRYPTED ENVELOPE");
        }
        return null;
    }

    public static Envelope decryptEnvelope(Envelope envelope, Cipher cipher, Cipher authenticationCipher, int message_count) {
        try {
            int AUTHENTICATION_SIZE = 8;
            byte[] decryptedEnvelope = cipher.doFinal((byte[]) envelope.getObjContents().get(0));
            byte[] authEnvelope = authenticationCipher.doFinal(decryptedEnvelope);
            byte[] residue = (byte[]) envelope.getObjContents().get(1);
            for (int i = 0; i < AUTHENTICATION_SIZE; i++) {
                if (Byte.compare(residue[i], authEnvelope[authEnvelope.length - AUTHENTICATION_SIZE + i]) != 0) {
                    System.out.println("MESSAGE TAMPERING DECTECTED!");
                    System.exit(0);
                }
            }
            ByteArrayInputStream byteToEnvelope = new ByteArrayInputStream(decryptedEnvelope);
            ObjectInputStream ois = new ObjectInputStream(byteToEnvelope);
            Envelope decrypted = (Envelope) ois.readObject();
            int message_number = (int) decrypted.getObjContents().get(decrypted.getObjContents().size() - 1);
            if (message_count != message_number) {
                System.out.println("MESSAGE MANIPULATION DETECTED!");
                System.exit(0);
            }
            decrypted.getObjContents().remove(decrypted.getObjContents().size() - 1);
            return decrypted;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("DECRYPTION FAILURE!");
        }
        return null;
    }

    public static Envelope decryptEnvelope(Envelope envelope, Cipher cipher) {
        try {
            byte[] decryptedEnvelope = cipher.doFinal((byte[]) envelope.getObjContents().get(0));
            ByteArrayInputStream byteToEnvelope = new ByteArrayInputStream(decryptedEnvelope);
            ObjectInputStream ois = new ObjectInputStream(byteToEnvelope);
            return (Envelope) ois.readObject();

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("DECRYPTION FAILURE");
        }
        return null;
    }
}
