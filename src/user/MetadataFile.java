package user;

import javax.crypto.spec.IvParameterSpec;
import java.io.Serializable;

public class MetadataFile implements Serializable {
    private static final long serialVersionUID = 206216459759358216L;
    private byte[] IV;
    private int hashVersion;
    private byte[] ciphertext;

    public MetadataFile(IvParameterSpec IV, int hashVersion, byte[] ciphertext) {
        this.IV = IV.getIV();
        this.hashVersion = hashVersion;
        this.ciphertext = ciphertext;
    }

    public byte[] getIV() {
        return IV;
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public int getHashVersion() {
        return hashVersion;
    }

    public void setHashVersion(int hashVersion) {
        this.hashVersion = hashVersion;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }


}
