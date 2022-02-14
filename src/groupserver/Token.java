package groupserver;

import java.security.PublicKey;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import other.UserToken;

/**
 * A simple interface to the token data structure that will be returned by a
 * group server.
 *
 * You will need to develop a class that implements this interface so that your
 * code can interface with the tokens created by your group server.
 *
 */
final class Token extends UserToken {

    private final String issuer;
    private final String subject;
    private final List<String> groups;
    private final Hashtable<String, GroupMetaData> groupMetaData;
    private final byte[] hash;

    public Token(String issuer, String subject, ArrayList<String> groups, Hashtable<String, GroupMetaData> groupMetaData, Cipher signatureCipher, PublicKey serverKey) throws IllegalBlockSizeException, BadPaddingException {
        checkMatch(issuer);
        checkMatch(subject);
        checkMatch(groups);
        this.issuer = issuer;
        this.subject = subject;
        this.groups = new ArrayList<>(groups);
        this.hash = signatureCipher.doFinal(getHash(serverKey));
        this.groupMetaData = groupMetaData;
    }

    private void checkMatch(String str) {
        if (str.contains("\n")) {
            throw new IllegalArgumentException("Error: String contains illegal newline character");
        }
    }

    private void checkMatch(List<String> groups) {
        groups.forEach((group) -> {
            checkMatch(group);
        });
    }

    /**
     * This method should return a string describing the issuer of this token.
     * This string identifies the group server that created this token. For
     * instance, if "Alice" requests a token from the group server "Server1",
     * this method will return the string "Server1".
     *
     * @return The issuer of this token
     *
     */
    @Override
    public String getIssuer() {
        return issuer;
    }

    /**
     * This method should return a string indicating the name of the subject of
     * the token. For instance, if "Alice" requests a token from the group
     * server "Server1", this method will return the string "Alice".
     *
     * @return The subject of this token
     *
     */
    @Override
    public String getSubject() {
        return subject;
    }

    /**
     * This method extracts the list of groups that the owner of this token has
     * access to. If "Alice" is a member of the groups "G1" and "G2" defined at
     * the group server "Server1", this method will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    @Override
    public List<String> getGroups() {
        return groups;
    }

    @Override
    public byte[] getSignedHash() {
        return hash; 
    }

    @Override
    public Hashtable<String, GroupMetaData> getGroupMetaData() {
        return groupMetaData;
    }
}   //-- end interface UserToken
