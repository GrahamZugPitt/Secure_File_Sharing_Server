package groupserver;

import other.CryptographicFunctions;

import javax.crypto.SecretKey;

public class GroupMetaData implements java.io.Serializable {

    private static final long serialVersionUID = 2918891956268568942L;
    private SecretKey currentKey;
    private int keyIndex;


    public GroupMetaData(SecretKey seedKey, int keyIndex) {
        this.currentKey = CryptographicFunctions.hashKey(seedKey, keyIndex);
        this.keyIndex = keyIndex;
    }

    public SecretKey getCurrentKey() {
        return currentKey;
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public void updateCurrentKey(SecretKey seedKey) {
        this.keyIndex = keyIndex--;
        this.currentKey = CryptographicFunctions.hashKey(seedKey, keyIndex);
    }
}
