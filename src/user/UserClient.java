package user;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;
import other.UserToken;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import other.CryptographicFunctions;

import javax.crypto.spec.IvParameterSpec;

public class UserClient {

    private static final GroupClient group_client = new GroupClient();
    private static final FileClient file_client = new FileClient();

    public static final String[] adminOperations = {"Create User", "Delete User"};
    public static final String[] groupOperations = {"Create Group", "Delete Group", "Add User to Group", "Delete User From Group", "List Members"};
    public static final String[] fileOperations = {"List Files", "Upload", "Download", "Delete"};
    private static final String[] propOp = {"List Groups"};
    private String password = null;

    public UserClient() {
        Security.addProvider(new BouncyCastleProvider());
        try ( Scanner keyboard = new Scanner(System.in)) {
            run(keyboard);
        }
    }

    public UserClient(Scanner input) {
        run(input);
    }

    private void run(Scanner input) {
        boolean re = tryConnect(input, group_client, "Group Server");
        if (re == false) {
            return;
        }
        re = tryConnect(input, file_client, "File Server");
        if (re == false) {
            group_client.disconnect();
            return;
        }
        UserToken groupToken = authenticate(input);
        UserToken fileToken = group_client.getToken(groupToken.getSubject(), password, file_client.publicKey);
        List<String> groups = groupToken.getGroups();

        ArrayList<String> list = new ArrayList<>();
        if (groups.contains("ADMIN")) {
            addAll(list, adminOperations);
        }
        addAll(list, groupOperations);
        addAll(list, propOp);
        addAll(list, fileOperations);

        String[] operations = list.toArray(new String[list.size()]);
        while (runMenu(input, operations, groupToken, fileToken) == false) {
            groupToken = group_client.getToken(groupToken.getSubject(), password, group_client.publicKey);
            fileToken = group_client.getToken(fileToken.getSubject(), password, file_client.publicKey);
        }

        group_client.disconnect();
        file_client.disconnect();
    }

    private void addAll(List<String> list, String[] arr) {
        list.addAll(Arrays.asList(arr));
    }

    private boolean runMenu(Scanner input, String[] operations, UserToken groupToken, UserToken fileToken) {
        System.out.println("List of valid operations:");
        for (int i = 0; i < operations.length; i++) {
            System.out.printf("  %d. %s\n", i + 1, operations[i]);
        }
        System.out.printf("  %d. Disconnect\n", operations.length + 1);
        System.out.println();

        int choice = 0;
        boolean invalid = true;
        do {
            System.out.print("Please input an integer to represent your choice: ");
            String choiceStr = input.nextLine();
            try {
                choice = Integer.parseInt(choiceStr) - 1;
                if (choice >= 0 && choice <= operations.length) {
                    invalid = false;
                } else {
                    System.out.printf("Please input an integer between %d - %d\n", 1, operations.length + 1);
                }
            } catch (NumberFormatException ex) {
                System.out.println("\nPlease input a valid integer for your choice.");
            }
            System.out.println();
        } while (invalid);

        if (choice == operations.length) {
            return true;
        }

        String output = operations[choice];
        boolean re = false;
        switch (output) {
            case "Create User":
                String username = getStr("Please enter username", input);
                String user_password = getStr("Please enter password", input);
                re = group_client.createUser(username, user_password, groupToken);
                break;
            case "Delete User":
                username = getStr("Please enter username", input);
                re = group_client.deleteUser(username, groupToken);
                break;
            case "Create Group":
                re = group_client.createGroup(getStr("Please enter group name", input), groupToken);
                break;
            case "Delete Group":
                re = group_client.deleteGroup(getStr("Please enter group name", input), groupToken);
                break;
            case "Add User to Group":
                username = getStr("Please enter username", input);
                String groupname = getStr("Please enter group name", input);
                re = group_client.addUserToGroup(username, groupname, groupToken);
                break;
            case "Delete User From Group":
                username = getStr("Please enter username", input);
                groupname = getStr("Please enter group name", input);
                re = group_client.deleteUserFromGroup(username, groupname, groupToken);
                break;
            case "List Members":
                groupname = getStr("Please enter group name", input);
                List<String> list = group_client.listMembers(groupname, groupToken);
                if (list != null) {
                    re = true;
                    System.out.printf("Members of %s:\n", groupname);
                    list.forEach((member) -> {
                        System.out.println('\t' + member);
                    });
                }
                break;
            case "List Files":
                list = file_client.listFiles(fileToken);
                if (list != null && !list.isEmpty()) {
                    re = true;
                    System.out.printf("Files you have access to: ");
                    list.forEach((file) -> {
                        System.out.println('\t' + file);
                    });
                } else {
                    System.out.println("No files found.");
                }
                break;
            case "Upload":
                String sourceFile = getStr("Please enter the source file", input);
                String destFile = getStr("Please enter the destination file", input);
                groupname = getStr("Please enter group name", input);
                re = file_client.upload(sourceFile, destFile, groupname, fileToken);
                break;
            case "Download":
                groupname = getStr("Please enter group name", input);
                sourceFile = getStr("Please enter the source file", input);
                destFile = getStr("Please enter the destination file", input);
                re = file_client.download(groupname, sourceFile, destFile, fileToken);
                break;
            case "Delete":
                groupname = getStr("Please enter group name", input);
                sourceFile = getStr("Please enter the file to delete", input);
                re = file_client.delete(groupname, sourceFile, fileToken);
                break;
            case "List Groups":
                list = groupToken.getGroups();
                if (list != null && !list.isEmpty()) {
                    System.out.printf("Groups you have access to: ");
                    list.forEach((file) -> {
                        System.out.println('\t' + file);
                    });
                } else if (list == null) {
                    System.out.println("No groups found.");
                }
                re = true;
                break;
            default:
                System.out.println("That command isn't supported yet!");
        }

        if (re == false) {
            System.out.println("Operation was unsucessful!");
        }

        System.out.println();

        return false;
    }

    private static String getStr(String prompt, Scanner input) {
        System.out.printf("%s: ", prompt);
        return input.nextLine();
    }

    private static boolean tryConnect(Scanner input, Client client, String client_name) {
        boolean invalid = true;
        do {
            System.out.printf("Please enter the ip address of the %s (Type 'exit' to exit program): ", client_name);
            String ip = input.nextLine();
            if (ip.equalsIgnoreCase("exit")) {
                return false;
            }

            System.out.print("Please enter the open port: ");
            String portStr = input.nextLine();

            System.out.print("Please enter the encoded RSA key for the server: ");
            String keyStr = input.nextLine();

            try {
                int port = Integer.parseInt(portStr);
                PublicKey serverKey = CryptographicFunctions.decodePublicRSAKey(keyStr);
                invalid = !client.connect(ip, port, serverKey);
            } catch (NumberFormatException ex) {
                System.out.println("\nPlease input a valid integer for the port.");
            } catch (GeneralSecurityException ex) {
                System.out.println("\nError: " + ex);
                System.out.println("Please input a RSA key.");
            }
            System.out.println();
        } while (invalid);

        return true;
    }

    private UserToken authenticate(Scanner input) {
        boolean invalid = true;
        UserToken token = null;
        do {
            System.out.print("Please input your username: ");
            String username = input.nextLine();
            System.out.print("Please input your password: ");
            password = input.nextLine();
            token = group_client.getToken(username, password, group_client.publicKey);
            if (token != null) {
                invalid = false;
            }
        } while (invalid);
        return token;
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            new UserClient();
        } else {
            try {
                new UserClient(new Scanner(new File(args[0])));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

}
