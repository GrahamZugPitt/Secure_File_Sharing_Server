package groupserver;

/* Group server. Server loads the users from UserList.bin and then loads the groups from GroupList.bin
 * If user list does not exists, it creates a new user and group list, makes the user the server administrator and owner of the ADMIN group.
 * On exit, the server saves the user list to file and saves the group list to file.
 */
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import other.CryptographicFunctions;
import other.Server;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;
import other.Envelope;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;
    private final String userFile = "UserList.bin";
    private final String groupFile = "GroupList.bin";
    private final String RSAKeyFile = "RSAKeyFile.bin";

    PublicKey publicKey;
    Cipher rsaSignatureCipher;
    Cipher rsaVerificationCipher;
    Cipher rsaDecryptionCipher;

    public GroupServer(int _port) {
        super(_port, "alpha");
    }

    @Override
    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created
        Security.addProvider(new BouncyCastleProvider());

        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;
        ObjectInputStream RSAKeyStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        KeyPair keyPair = null;
        try {
            try {
                //Open user file to get user list
                userStream = new ObjectInputStream(new FileInputStream(userFile));
                userList = (UserList) userStream.readObject();

                //Open group file to get group list
                groupStream = new ObjectInputStream(new FileInputStream(groupFile));
                groupList = (GroupList) groupStream.readObject();

                //Open key file to get public key
                RSAKeyStream = new ObjectInputStream(new FileInputStream(RSAKeyFile));
                keyPair = (KeyPair) RSAKeyStream.readObject();
            } catch (FileNotFoundException e) {
                System.out.println("UserList File Does Not Exist. Creating UserList...");
                System.out.println("No users currently exist. Your account will be the administrator.");
                System.out.print("Enter your username: ");
                String username = console.next();
                System.out.print("Enter your password: ");
                String password = console.next();
                byte[] hashedPassword = CryptographicFunctions.hash(password.getBytes());

                //Create a new userlist, add current user to the ADMIN group. They now own the ADMIN group.
                userList = new UserList();
                userList.addUser(username, hashedPassword);
                userList.addOwnership(username, "ADMIN");

                System.out.println("Group Server key pair does not exist. Generating keys...");
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

                //Create a new groupList, add ADMIN group with current user as a member with ownership of the ADMIN group
                System.out.println("GroupList File Does Not Exist. Creating GroupList...");
                System.out.println("ADMIN group has been created. Your account will be the owner of ADMIN.");
                groupList = new GroupList();
                groupList.addGroup("ADMIN", username);
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        } catch (Exception e) {
            System.out.println(e);
            System.exit(-1);
        }

        try {
            publicKey = keyPair.getPublic();
            rsaSignatureCipher = CryptographicFunctions.createSignatureCipher(keyPair.getPrivate());
            rsaDecryptionCipher = CryptographicFunctions.createDecryptionCipher(keyPair.getPrivate());
            rsaVerificationCipher = CryptographicFunctions.createVerificationCipher(keyPair.getPublic());
        } catch (GeneralSecurityException ex) {
            System.out.println("Error reading KeyPair.");
            System.exit(-1);
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());
            System.out.printf("The public key is:\n%s\n", Hex.toHexString(keyPair.getPublic().getEncoded()));
            Socket sock;
            GroupThread thread;

            while (true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

    //This thread saves the user list
    class ShutDownListener extends Thread {

        public GroupServer my_gs;

        public ShutDownListener(GroupServer _gs) {
            my_gs = _gs;
        }

        @Override
        public void run() {
            System.out.println("Shutting down server");
            ObjectOutputStream userStream;
            ObjectOutputStream groupStream;
            try {
                userStream = new ObjectOutputStream(new FileOutputStream(my_gs.userFile));
                userStream.writeObject(my_gs.userList);

                groupStream = new ObjectOutputStream(new FileOutputStream(my_gs.groupFile));
                groupStream.writeObject(my_gs.groupList);

            } catch (IOException e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }

    class AutoSave extends Thread {

        public GroupServer my_gs;

        public AutoSave(GroupServer _gs) {
            my_gs = _gs;
        }

        @Override
        public void run() {
            do {
                try {
                    System.out.println("Autosave group and user lists...");
                    ObjectOutputStream userStream;
                    ObjectOutputStream groupStream;
                    try {
                        userStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                        userStream.writeObject(my_gs.userList);

                        groupStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                        groupStream.writeObject(my_gs.groupList);
                    } catch (IOException e) {
                        System.err.println("Error: " + e.getMessage());
                        e.printStackTrace(System.err);
                    }
                    Thread.sleep(300000); //Save group and user lists every 5 minutes
                } catch (InterruptedException e) {
                    System.out.println("Autosave Interrupted");
                }
            } while (true);
        }
    }
}
