package other;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import groupserver.GroupMetaData;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple interface to the token data structure that will be returned by a
 * group server.
 *
 * You will need to develop a class that implements this interface so that your
 * code can interface with the tokens created by your group server.
 *
 */
public abstract class UserToken implements Serializable {
    
    public static final int TOKEN_LIFETIME_MINUTES = 5;
    public final long EXPR_DATE = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(TOKEN_LIFETIME_MINUTES);
    
    /**
     * This method should return a string describing the issuer of this token.
     * This string identifies the group server that created this token. For
     * instance, if "Alice" requests a token from the group server "Server1",
     * this method will return the string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public abstract String getIssuer();

    /**
     * This method should return a string indicating the name of the subject of
     * the token. For instance, if "Alice" requests a token from the group
     * server "Server1", this method will return the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public abstract String getSubject();

    /**
     * This method extracts the list of groups that the owner of this token has
     * access to. If "Alice" is a member of the groups "G1" and "G2" defined at
     * the group server "Server1", this method will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public abstract List<String> getGroups();

    @Override
    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getIssuer()).append('\n');
        sb.append(getSubject()).append('\n');
        List<String> groups = getGroups();
        Collections.sort(groups);
        groups.forEach((group) -> {
            sb.append(group).append('\n');
        });
        return sb.toString();
    }

    public final byte[] getHash(PublicKey serverKey) {
        return CryptographicFunctions.hash((toString() + "\n" + Hex.toHexString(serverKey.getEncoded())).getBytes());
    }
    
    public abstract byte[] getSignedHash();
    
    public final boolean confirmHash(Cipher rsaVerificationCipher, PublicKey serverKey){
        
        if(EXPR_DATE - System.currentTimeMillis() < 0){
            System.out.println("\tToken expired.");
            return false;
        }
        
        try {
            return Arrays.equals(getHash(serverKey), rsaVerificationCipher.doFinal(getSignedHash()));
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public abstract Hashtable<String, GroupMetaData> getGroupMetaData();


}   //-- end interface UserToken
