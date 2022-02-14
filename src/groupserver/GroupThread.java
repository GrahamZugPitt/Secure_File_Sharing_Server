package groupserver;

/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import other.Envelope;
import other.UserToken;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import other.CryptographicFunctions;

public class GroupThread extends Thread {

    private final static SecureRandom rand = new SecureRandom();
    private final static Integer CHALLENGE_DIFFICULTY = 3;
    private final static Integer SALT_SIZE = 256;

    // A list of all invalid characters to put in a String. These characters may interact with the filesystem and should nt be allowed.
    private static final Pattern INVALID_STRING_PATTERN = Pattern.compile("(\\.|\n|~|:|\\\\|\\/|\\?|\\*|¥|%|\\\"|<|>| |,|;|=)");

    private final Socket socket;
    private final GroupServer my_gs;

    private IvParameterSpec nextIv = null;
    private IvParameterSpec nextIvAuth = null;
    private SecretKey symmetric_key = null;
    private SecretKey authentication_key = null;
    int message_number = 0;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

    @Override
    public void run() {
        boolean proceed = true;
        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;

            if (challengeDOS(output, input)) {
                do {
                    Envelope message = (Envelope) input.readObject();

                    if (message.getMessage().equals("ENCRYPTED")) {
                        if (symmetric_key == null) {
                            message = Envelope.decryptEnvelope(message, my_gs.rsaDecryptionCipher);
                        } else {
                            message = Envelope.decryptEnvelope(message, CryptographicFunctions.createDecryptionCipher(symmetric_key, nextIv), CryptographicFunctions.createEncryptionCipher(authentication_key, nextIvAuth), message_number);
                        }

                    }
                    System.out.println("Request received: " + message.getMessage());
                    response = new Envelope("FAIL");
                    ArrayList<Object> messageContents = message.getObjContents();
                    switch (message.getMessage()) {
                        case "GET":
                            //Client wants a token
                            if (validateArguments(messageContents, new Class[]{String.class, byte[].class, PublicKey.class})) {
                                @SuppressWarnings("unchecked")
                                String username = (String) messageContents.get(0); //Get the username
                                @SuppressWarnings("unchecked")
                                byte[] password = (byte[]) messageContents.get(1); //Get the password
                                @SuppressWarnings("unchecked")
                                PublicKey serverKey = (PublicKey) messageContents.get(2); //Get the PublicKey of the server for the token

                                if (my_gs.userList.verifyUser(username, password)) {
                                    UserToken yourToken = createToken(username, password, serverKey); //Create a token
                                    //Respond to the client. On error, the client will receive a null token
                                    System.out.printf("\tFound token: %s\n", yourToken);
                                    response = new Envelope("OK");
                                    response.addObject(yourToken);
                                }
                            }
                            break;
                        case "CUSER":
                            //Client wants to create a user
                            if (validateArguments(messageContents, new Class[]{String.class, byte[].class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String username = (String) messageContents.get(0); //Extract the username
                                @SuppressWarnings("unchecked")
                                byte[] password = (byte[]) messageContents.get(1); //Extract the password
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(2); //Extract the token

                                if (createUser(username, password, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                            break;
                        case "DUSER":
                            //Client wants to delete a user
                            if (validateArguments(messageContents, new Class[]{String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String username = (String) messageContents.get(0); //Extract the username
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(1); //Extract the token

                                if (deleteUser(username, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                            break;
                        //Client wants to create a group
                        case "CGROUP":
                            if (validateArguments(messageContents, new Class[]{String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String groupname = (String) messageContents.get(0);
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(1);

                                if (createGroup(groupname, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                            break;
                        //Client wants to delete a group
                        case "DGROUP":
                            if (validateArguments(messageContents, new Class[]{String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String groupname = (String) messageContents.get(0);
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(1);

                                if (deleteGroup(groupname, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                            break;
                        //Client wants a list of members in a group
                        case "LMEMBERS":
                            if (validateArguments(messageContents, new Class[]{String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String groupname = (String) messageContents.get(0);
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(1);

                                if (my_gs.groupList.checkGroup(groupname) && my_gs.groupList.getGroupOwner(groupname).compareTo(yourToken.getSubject()) == 0) {
                                    response = new Envelope("OK");
                                    ArrayList<String> temp = new ArrayList<>();
                                    for (int i = 0; i < my_gs.groupList.getMembersFromGroup(groupname).size(); i++) {
                                        temp.add(my_gs.groupList.getMembersFromGroup(groupname).get(i));
                                    }
                                    response.addObject(temp);
                                }
                            }
                            break;
                        //Client wants to add user to a group
                        case "AUSERTOGROUP":
                            if (validateArguments(messageContents, new Class[]{String.class, String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String userBeingAdded = (String) messageContents.get(0);
                                @SuppressWarnings("unchecked")
                                String groupname = (String) messageContents.get(1);
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(2);

                                if (my_gs.groupList.checkGroup(groupname) && my_gs.groupList.getGroupOwner(groupname).compareTo(yourToken.getSubject()) == 0) {
                                    if (addUserToGroup(groupname, userBeingAdded)) {
                                        response = new Envelope("OK");
                                    }
                                }
                            }
                            break;
                        //Client wants to remove user from a group
                        case "RUSERFROMGROUP":
                            if (validateArguments(messageContents, new Class[]{String.class, String.class, UserToken.class})) {
                                @SuppressWarnings("unchecked")
                                String userBeingRemoved = (String) messageContents.get(0);
                                @SuppressWarnings("unchecked")
                                String groupname = (String) messageContents.get(1);
                                @SuppressWarnings("unchecked")
                                UserToken yourToken = (UserToken) messageContents.get(2);

                                if (my_gs.groupList.checkGroup(groupname) && my_gs.groupList.getGroupOwner(groupname).compareTo(yourToken.getSubject()) == 0) {
                                    if (removeUserFromGroup(groupname, userBeingRemoved)) {
                                        response = new Envelope("OK");
                                    }
                                }
                            }
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
                        case "DISCONNECT":
                            //Client wants to disconnect
                            socket.close(); //Close the socket
                            proceed = false; //End this communication loop
                            break;
                        default:
                            System.out.println("Unknown Operation!");
                            break;
                    }

                    if (proceed == true) {
                        encryptAndSend(output, response);
                    }

                } while (proceed);
            } else {
                System.out.println("[FAILED DOS CHALLENGE]: connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            }

        } catch (Exception e) {
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
        } catch (GeneralSecurityException ex) {
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

    //Method to create tokens
    private UserToken createToken(String username, byte[] password, PublicKey serverKey) throws IllegalBlockSizeException, BadPaddingException {
        //Check that user exists
        if (my_gs.userList.verifyUser(username, password)) {
            //Issue a new token with server's name, user's name, and user's groups
            UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), my_gs.groupList.getGroupMetaData(my_gs.userList.getUserGroups(username)), my_gs.rsaSignatureCipher, serverKey);
            return yourToken;
        } else {
            return null;
        }
    }
    //method to create a group

    private boolean createGroup(String groupname, UserToken yourToken) throws GeneralSecurityException {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if (my_gs.userList.checkUser(requester)) {
            //Does the group already exist?
            if (my_gs.groupList.checkGroup(groupname)) {
                return false; //Group already exists
            } else {
                my_gs.groupList.addGroup(groupname, yourToken.getSubject());
                my_gs.userList.addOwnership(yourToken.getSubject(), groupname);
                return true;
            }

        } else {
            return false; //requester does not exist
        }
    }

    private boolean deleteGroup(String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if (my_gs.userList.checkUser(requester)) {
            //Does the group exist?
            if (!my_gs.groupList.checkGroup(groupname)) {
                return false; //Group does not exist
            }
            if (my_gs.groupList.getGroupOwner(groupname).compareTo(requester) != 0) {
                return false; //A non-group owner tried to delete the group
            } else {
                for (int i = 0; i < my_gs.groupList.getMembersFromGroup(groupname).size(); i++) {
                    removeUserFromGroup(groupname, my_gs.groupList.getMembersFromGroup(groupname).get(i));
                }
                my_gs.groupList.deleteGroup(groupname);
                return true;
            }

        } else {
            return false; //requester does not exist
        }
    }

    //Method to create a user
    private boolean createUser(String username, byte[] password, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists and that the user being created does not exist
        if (my_gs.userList.checkUser(requester) && password != null) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if (temp.contains("ADMIN")) {
                //Does user already exist?
                if (my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username, password);
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    private boolean addUserToGroup(String group, String username) {
        if (my_gs.userList.checkUser(username) && !my_gs.userList.getUserGroups(username).contains(group)) {
            my_gs.groupList.addMemberToGroup(group, username);
            my_gs.userList.addGroup(username, group);
            return true;
        }
        return false;
    }

    private boolean removeUserFromGroup(String group, String username) {
        if (my_gs.userList.checkUser(username) && my_gs.userList.getUserGroups(username).contains(group)) {
            my_gs.groupList.deleteMemberFromGroup(group, username);
            my_gs.userList.removeGroup(username, group);
            return true;
        }
        return false;
    }

    //Method to delete a user
    private boolean deleteUser(String username, UserToken yourToken) throws IllegalBlockSizeException, BadPaddingException {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if (my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if (temp.contains("ADMIN")) {
                //Does user exist?
                if (my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for (int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for (int index = 0; index < deleteFromGroups.size(); index++) {
                        removeUserFromGroup(deleteFromGroups.get(index), username);
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<>();

                    //Make a hard copy of the user's ownership list
                    for (int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    Hashtable<String, GroupMetaData> deleteOwnedGroupMetaData = my_gs.groupList.getGroupMetaData(deleteOwnedGroup);

//                    //Delete owned groups (I'm assuming this is superflous because removeUserFromGroup())
                    for (int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, deleteOwnedGroupMetaData, my_gs.rsaSignatureCipher, my_gs.publicKey));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    return true;
                } else {
                    return false; //User does not exist

                }
            } else {
                return false; //requester is not an administer
            }
        } else {
            return false; //requester does not exist
        }
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

                if (!token.confirmHash(my_gs.rsaVerificationCipher, my_gs.publicKey)) {
                    System.out.println("\tReceived token is forged!");
                    return false;
                }
            }
        }
        return true;
    }
}
