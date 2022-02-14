package fileserver;

/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import other.Server;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;
import other.CryptographicFunctions;

public class FileServer extends Server {

    PublicKey rsaPublicKey;
    Cipher rsaVerificationCipher;
    Cipher rsaDecryptionCipher;

    private final static String RSAKeyFile = "FileServerRSAKeyFile.bin";
    private final static String RSAVerifyKeyFile = "FileServerRSAVerifyKeyFile.bin";
    private final static int RSAKeySize = 1100;

    public FileServer(int _port) {
        super(_port, "omega");
    }


    @Override
    public void start() {
        Security.addProvider(new BouncyCastleProvider());

        ObjectInputStream RSAKeyStream;

        //Open user file to get user list
        KeyPair keyPair;
        try {
            RSAKeyStream = new ObjectInputStream(new FileInputStream(RSAKeyFile));
            keyPair = (KeyPair) RSAKeyStream.readObject();

        } catch (IOException | ClassNotFoundException e) {
            System.out.println("File Server key pair does not exist. Generating keys...");
            keyPair = CryptographicFunctions.generateRSAKeyPair();
            ObjectOutputStream keyStream;
            try {
                keyStream = new ObjectOutputStream(new FileOutputStream(RSAKeyFile));
                keyStream.writeObject(keyPair);
            } catch (IOException ex) {
                System.err.println("Could not save public key file.");
                System.err.println("Exiting program.");
                System.exit(-1);
            }
        }
        System.out.printf("The public key is:\n%s\n", Hex.toHexString(keyPair.getPublic().getEncoded()));

        try {
            rsaPublicKey = keyPair.getPublic();
            rsaDecryptionCipher = CryptographicFunctions.createDecryptionCipher(keyPair.getPrivate());
            Scanner userInput = new Scanner(System.in);
            System.out.println("Please input the public key for the GroupServer: ");
            String keyname = userInput.nextLine().trim();
            userInput.close();
            if(keyname.length() < RSAKeySize){
                System.out.println("Input is less than length of expected key. Looking for key file: " + keyname);
                String text = new String(Files.readAllBytes(Paths.get(keyname)), StandardCharsets.UTF_8);
                keyname = text;
            }
            PublicKey key = CryptographicFunctions.decodePublicRSAKey(keyname);
            rsaVerificationCipher = CryptographicFunctions.createVerificationCipher(key);
        } catch (GeneralSecurityException | FileNotFoundException ex) {
            System.out.println("Error reading Key.");
            System.exit(-1);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock;
            Thread thread;

            while (true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, this);
                thread.start();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
