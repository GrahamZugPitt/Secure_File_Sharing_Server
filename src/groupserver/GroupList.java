package groupserver;


import javax.crypto.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import other.CryptographicFunctions;

public class GroupList implements java.io.Serializable{

    /*Serializable so it can be stored in a file for persistence */
    private static final long serialVersionUID = -8590174706639205273L;
    private Hashtable<String, GroupList.Group> list = new Hashtable<String, GroupList.Group>();

    public synchronized void addGroup(String groupname, String owner) throws GeneralSecurityException {
        list.put(groupname, new Group(groupname, owner));
    }

    public synchronized void deleteGroup(String groupname){
        list.remove(groupname);
    }

    public synchronized boolean checkGroup(String groupname){
        return list.containsKey(groupname);
    }

    public synchronized String getGroupOwner(String groupname){
        return list.get(groupname).getOwner();
    }

    public synchronized GroupMetaData getGroupMetaData(String groupname){
        return list.get(groupname).getMetaData();
    }

    public synchronized Hashtable<String, GroupMetaData> getGroupMetaData(List<String> groupnames){
        Hashtable<String, GroupMetaData> groupMetaData = new Hashtable<>();
        for(String groupname: groupnames){
            groupMetaData.put(groupname, getGroupMetaData(groupname));
        }
        return groupMetaData;
    }
    public synchronized boolean checkGroupMember(String groupname, String user){
        return list.get(groupname).checkMember(user);
    }

    public synchronized void addMemberToGroup(String groupname, String user){
        list.get(groupname).addMember(user);
    }

    public synchronized boolean deleteMemberFromGroup(String groupname, String user){
        return list.get(groupname).deleteMember(user);
    }

    public synchronized ArrayList<String> getMembersFromGroup(String groupname){
        return list.get(groupname).getMembers();
    }


    class Group implements java.io.Serializable {
        /**
         *
         */
        private static final long serialVersionUID = -2252186368468557992L;
        private static final int INITIAL_HASHES = 1000;
        private static final int AES_KEYSIZE = 256;
        private String name;
        private ArrayList<String> members;
        private String owner;
        private SecretKey seedKey;
        private GroupMetaData metaData;

        public Group(String name, String owner) throws GeneralSecurityException {
            this.name = name;
            this.members = new ArrayList<>();
            this.members.add(owner);
            this.owner = owner;

            //for file encryption
            this.seedKey = CryptographicFunctions.generateAESKey(AES_KEYSIZE);
            this.metaData = new GroupMetaData(seedKey, INITIAL_HASHES);
        }

        public SecretKey getKey(){
            return metaData.getCurrentKey();
        }

        public String getName() {
            return name;
        }

        public ArrayList<String> getMembers() {
            return members;
        }

        public String getOwner(){return owner;}

        public GroupMetaData getMetaData() {
            return metaData;
        }

        public void addMember(String user){
            members.add(user);
        }

        public boolean deleteMember(String user) {
            if (user.equals(owner)) {
                return false;
            } else {
                members.remove(user);
                metaData.updateCurrentKey(seedKey);
                return true;
            }
        }

        public void changeOwner(String newOwner){
            owner = newOwner;
        }

        public boolean checkMember(String user){return members.contains(user);}

    }

}
