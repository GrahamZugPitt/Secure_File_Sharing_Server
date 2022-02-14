package user;

/* Implements the GroupClient Interface */
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import other.CryptographicFunctions;
import other.UserToken;

/*	Signature signature; 
	signature = Signature.getInstance("SHA256WithRSA");
	signature.initSign(keyPair.getPrivate());
*/
public class GroupClient extends Client implements GroupClientInterface {
    
    @Override
    public UserToken getToken(String username, String password, PublicKey key) {
        byte[] hashedPassword = CryptographicFunctions.hash(password.getBytes());
        return this.<UserToken>sendMessageObject("GET", new Object[]{username, hashedPassword, key});
    }

    @Override
    public boolean createUser(String username, String password, UserToken token) {
        byte[] hashedPassword = CryptographicFunctions.hash(password.getBytes());
        return sendMessage("CUSER", new Object[]{username, hashedPassword, token});
    }

    @Override
    public boolean deleteUser(String username, UserToken token) {
        return sendMessage("DUSER", new Object[]{username, token});
    }

    @Override
    public boolean createGroup(String groupname, UserToken token) {
        return sendMessage("CGROUP", new Object[]{groupname, token});
    }

    @Override
    public boolean deleteGroup(String groupname, UserToken token) {
        return sendMessage("DGROUP", new Object[]{groupname, token});
    }

    @Override
    public List<String> listMembers(String group, UserToken token) {
        return sendMessageObject("LMEMBERS", new Object[]{group, token});
    }

    @Override
    public ArrayList<String> listGroups(UserToken token) {
        return sendMessageObject("LGROUPS", new Object[]{token});
    }

    @Override
    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        return sendMessage("AUSERTOGROUP", new Object[]{username, groupname, token});
    }

    @Override
    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        return sendMessage("RUSERFROMGROUP", new Object[]{username, groupname, token});
    }
}
