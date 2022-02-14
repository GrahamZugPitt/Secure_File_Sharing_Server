package fileserver;

/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */
import java.net.Socket;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import other.Envelope;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import other.UserToken;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import other.CryptographicFunctions;

public class FileThread extends Thread {

    private final static SecureRandom rand = new SecureRandom();
    private final static Integer CHALLENGE_DIFFICULTY = 3;
    private final static Integer SALT_SIZE = 256;

    // A list of all invalid characters to put in a String. These characters may interact with the filesystem and should nt be allowed.
    private static final Pattern INVALID_STRING_PATTERN = Pattern.compile("(\\.\\.|\n|~|:|\\.\\|\\.\\/|\\?|\\*|¥|%|\\\"|<|>| |,|;|=)");

    private final Socket socket;
    private final FileServer my_fs;

    private IvParameterSpec nextIv = null;
    private SecretKey symmetric_key = null;
    private IvParameterSpec nextIvAuth = null;
    private SecretKey authentication_key = null;
    int message_number = 0;

    public FileThread(Socket _socket, FileServer _fs) {
        socket = _socket;
        my_fs = _fs;
    }

    public void run() {
        boolean proceed = true;
        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;

            if (challengeDOS(output, input)) {
                do {
                    Envelope message = (Envelope) input.readObject();

                    if (message.getMessage().equals("ENCRYPTED")) {
                        if (symmetric_key == null) {
                            message = Envelope.decryptEnvelope(message, my_fs.rsaDecryptionCipher);
                        } else {
                            message = Envelope.decryptEnvelope(message, CryptographicFunctions.createDecryptionCipher(symmetric_key, nextIv), CryptographicFunctions.createEncryptionCipher(authentication_key, nextIvAuth), message_number);
                        }

                    }
                    System.out.println("Request received: " + message.getMessage());
                    response = new Envelope("FAIL");
                    ArrayList<Object> messageContents = message.getObjContents();

                    // Handler to list files that this user is allowed to see
                    try {
                        switch (message.getMessage()) {
                            case "INITIALIZE":
                                if (validateArguments(messageContents, new Class[]{SecretKey.class, SecretKey.class})) {
                                    @SuppressWarnings("unchecked")
                                    SecretKey key = (SecretKey) messageContents.get(0);
                                    SecretKey key_auth = (SecretKey) messageContents.get(1);
                                    symmetric_key = key;
                                    authentication_key = key_auth;
                                    response = new Envelope("OK");
                                }
                                break;
                            case "LFILES":
                                if (validateArguments(messageContents, new Class[]{UserToken.class})) {
                                    @SuppressWarnings("unchecked")
                                    UserToken token = (UserToken) messageContents.get(0);

                                    ArrayList<String> list = listFiles(token);
                                    if (list != null) {
                                        response = new Envelope("OK");
                                        response.addObject(list);
                                    } else {
                                        response = new Envelope("OK");
                                    }
                                }
                                break;
                            case "UPLOADF":
                                if (validateArguments(messageContents, new Class[]{String.class, String.class, byte[].class, UserToken.class})) {
                                    @SuppressWarnings("unchecked")
                                    String group = (String) messageContents.get(0);
                                    @SuppressWarnings("unchecked")
                                    String path = (String) messageContents.get(1);
                                    @SuppressWarnings("unchecked")
                                    byte[] fileBytes = (byte[]) messageContents.get(2);
                                    @SuppressWarnings("unchecked")
                                    UserToken token = (UserToken) messageContents.get(3);

                                    if (token.getGroups().contains(group)) {
                                        File fi = new File(String.format("files/%s/%s", group, path));
                                        File dir = fi.getParentFile();
                                        dir.mkdirs();
                                        Files.write(fi.toPath(), fileBytes);
                                        //my_fs.fileList.addFile(token.getSubject(), group, path);
                                        response = new Envelope("OK");
                                    } else {
                                        System.out.println("\tInvalid group requested");
                                    }
                                }
                                break;
                            case "DOWNLOADF":
                                if (validateArguments(messageContents, new Class[]{String.class, String.class, UserToken.class})) {
                                    @SuppressWarnings("unchecked")
                                    String group = (String) messageContents.get(0);
                                    @SuppressWarnings("unchecked")
                                    String path = (String) messageContents.get(1);
                                    @SuppressWarnings("unchecked")
                                    UserToken token = (UserToken) messageContents.get(2);

                                    if (token.getGroups().contains(group)) {
                                        File fi = new File(String.format("files/%s/%s", group, path));
                                        byte[] arr = Files.readAllBytes(fi.toPath());
                                        response = new Envelope("OK");
                                        response.addObject(arr);
                                    } else {
                                        System.out.println("\tInvalid group requested");
                                    }
                                }
                                break;
                            case "DELETEF":
                                if (validateArguments(messageContents, new Class[]{String.class, String.class, UserToken.class})) {
                                    @SuppressWarnings("unchecked")
                                    String group = (String) messageContents.get(0);
                                    @SuppressWarnings("unchecked")
                                    String path = (String) messageContents.get(1);
                                    @SuppressWarnings("unchecked")
                                    UserToken token = (UserToken) messageContents.get(2);

                                    if (token.getGroups().contains(group)) {
                                        File fi = new File(String.format("files/%s/%s", group, path));
                                        Files.delete(fi.toPath());
                                        //my_fs.fileList.removeFile(group, path);
                                        response = new Envelope("OK");
                                    } else {
                                        System.out.println("\tInvalid group requested");
                                    }
                                }
                                break;
                            case "DISCONNECT":
                                //Client wants to disconnect
                                socket.close(); //Close the socket
                                proceed = false; //End this communication loop
                                break;
                            default:
                                System.out.println("Unknown Operation!");
                                break;
                        }
                    } catch (IOException ex) {
                        System.out.println("\tCould not do operation: " + ex);
                    }

                    if (proceed == true) {
                        encryptAndSend(output, response);
                    }

                } while (proceed);
            }
            else {
                System.out.println("[FAILED DOS CHALLENGE]: connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");                
            }
        } catch (ClassNotFoundException | IOException | GeneralSecurityException e) {
            //e.printStackTrace();
            System.err.println("Error: " + e.getMessage());
        }
    }

    private void encryptAndSend(ObjectOutputStream output, Envelope response) throws IOException {
        try {
            System.out.printf("\tReturning %s message.\n", response.getMessage());
            IvParameterSpec iv = CryptographicFunctions.generateIV();
            IvParameterSpec ivAuth = CryptographicFunctions.generateIV();
            nextIv = CryptographicFunctions.generateIV();
            nextIvAuth = CryptographicFunctions.generateIV();
            message_number++;

            Cipher aesEncryptionCipher = CryptographicFunctions.createEncryptionCipher(symmetric_key, iv);
            Cipher authenticationCipher = CryptographicFunctions.createEncryptionCipher(authentication_key, ivAuth);
            response = Envelope.encryptEnvelope(response, aesEncryptionCipher, authenticationCipher, message_number);
            response.addObject(iv.getIV());
            response.addObject(nextIv.getIV());
            response.addObject(ivAuth.getIV());
            response.addObject(nextIvAuth.getIV());
            output.writeObject(response);
        } catch (GeneralSecurityException | IOException ex) {
            System.out.println(ex);
            System.out.println("Could not write response.");
            output.writeObject(new Envelope("FAIL"));
        }
    }

    private static boolean challengeDOS(ObjectOutputStream output, ObjectInputStream input) {
        try {
            byte[] solution = new byte[CHALLENGE_DIFFICULTY];
            rand.nextBytes(solution);
            byte[] salt = new byte[SALT_SIZE];
            rand.nextBytes(salt);

            Envelope challengeMessage = new Envelope("CHALLENGE");
            challengeMessage.addObject(CryptographicFunctions.hash(solution, salt));
            challengeMessage.addObject(salt);
            challengeMessage.addObject(CHALLENGE_DIFFICULTY);
            output.writeObject(challengeMessage);

            Envelope response = (Envelope) input.readObject();
            List<Object> contents = response.getObjContents();

            if (response.getMessage().equals("RESPONSE")
                    && contents != null && contents.size() == 1
                    && contents.get(0) instanceof byte[]) {
                @SuppressWarnings("unchecked")
                byte[] arr = (byte[]) contents.get(0);
                return Arrays.equals(solution, arr);
            }
        } catch (IOException | ClassNotFoundException ex) {
            return false;
        }

        return false;
    }

    // Checks to see whether the objects in the recieved message form valid arguments
    private boolean validateArguments(ArrayList<Object> objects, Class[] argTypes) {
        assert (argTypes != null);

        if (objects == null || objects.size() != argTypes.length) {
            System.out.println("\tIncorrect number of arguments!");
            return false;
        }

        for (int i = 0; i < argTypes.length; i++) {
            Object elem = objects.get(i);

            if (elem == null || !argTypes[i].isAssignableFrom(elem.getClass())) {
                System.out.printf("\tExpected argument of type %s, but got argument of type %s!\n", argTypes[i], (elem == null) ? null : elem.getClass());
                return false;
            } // We require that no string should contain the newline character
            else if (elem.getClass().equals(String.class)) {
                @SuppressWarnings("unchecked")
                String str = (String) elem;

                if (INVALID_STRING_PATTERN.matcher(str).find()) {
                    System.out.println("\tString contains an invalid character!");
                    return false;
                }
            } // Check the token hasn't been forged 
            else if (UserToken.class.isAssignableFrom(elem.getClass())) {
                @SuppressWarnings("unchecked")
                UserToken token = (UserToken) elem;

                if (!token.confirmHash(my_fs.rsaVerificationCipher, my_fs.rsaPublicKey)) {
                    System.out.println("\tReceived token is forged!");
                    return false;
                }
            }
        }

        return true;
    }

    private ArrayList<String> listFiles(UserToken token) {
        ArrayList<String> list = new ArrayList<>();
        for (String group : token.getGroups()) {
            System.out.println("Group: " + group);
            File[] files = new File("files/" + group).listFiles();
            if (files != null) {
                for (File fi : files) {
                    list.add(fi.getPath());
                    System.out.println(fi.getPath());
                }
            }
        }
        return list;
    }
}
