package groupserver;

/* This list represents the users on the server */
import java.security.SecureRandom;
import java.util.*;

import other.CryptographicFunctions;

import javax.crypto.SecretKey;

public class UserList implements java.io.Serializable {
    private static final SecureRandom RAND_GEN = new SecureRandom();
    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, User> list = new Hashtable<>();

    public synchronized void addUser(String username, byte[] password) {
        User newUser = new User(password);
        list.put(username, newUser);
    }

    public synchronized void deleteUser(String username) {
        list.remove(username);
    }

    public synchronized boolean checkUser(String username) {
        return list.containsKey(username);
    }

    public synchronized boolean verifyUser(String username, byte[] password) {
        User user = list.get(username);
        System.out.println("\tUser is: "+user);
        if (user == null) {
            return false;
        }
        
        return user.comparePassword(password);
    }

    public synchronized ArrayList<String> getUserGroups(String username) {
        return list.get(username).getGroups();
    }


    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized void addGroup(String user, String groupname) {
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }

    class User implements java.io.Serializable {

        /**
         *
         */
        private static final long serialVersionUID = -6699986336399821598L;
        private final ArrayList<String> groups;
        private final ArrayList<String> ownership;

        private byte[] password;
        private final byte[] salt = new byte[10];

        public User(byte[] password) {
            groups = new ArrayList<>();
            ownership = new ArrayList<>();
            
            RAND_GEN.nextBytes(salt);
            this.password = CryptographicFunctions.hash(password, salt);
        }

        public byte[] getPassword() {
            return password;
        }

        public ArrayList<String> getGroups() {
            return groups;
        }


        public ArrayList<String> getOwnership() {
            return ownership;
        }

        public void addGroup(String group) {
            groups.add(group);
        }

        public void removeGroup(String group) {
            if (!groups.isEmpty()) {
                if (groups.contains(group)) {
                    groups.remove(groups.indexOf(group));
                }
            }
        }

        public void addOwnership(String group) {
            ownership.add(group);
            if (!groups.contains(group)) {
                groups.add(group);
            }
        }

        public void removeOwnership(String group) {
            if (!ownership.isEmpty()) {
                if (ownership.contains(group)) {
                    ownership.remove(ownership.indexOf(group));
                }
            }
        }
        
        public boolean comparePassword(byte[] checkPassword){
            byte[] hashedPassword = CryptographicFunctions.hash(checkPassword, salt);
            return Arrays.equals(hashedPassword, password);
        }
    }

}
