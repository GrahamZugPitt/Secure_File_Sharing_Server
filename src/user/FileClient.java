package user;

/* FileClient provides all the client functionality regarding the file server */
import java.io.*;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import other.CryptographicFunctions;
import other.UserToken;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FileClient extends Client implements FileClientInterface {

    public boolean delete(String groupname, String filename, UserToken token) {
        String remotePath;
        if (filename.charAt(0) == '/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }

        return sendMessage("DELETEF", new Object[]{groupname, remotePath, token});
    }

    public boolean download(String group, String sourceFile, String destFile, UserToken token) {
        if (sourceFile.charAt(0) == '/') {
            sourceFile = sourceFile.substring(1);
        }

        byte[] arr = sendMessageObject("DOWNLOADF", new Object[]{group, sourceFile, token});
        if (arr == null) {
            return false;
        }
        File fi = new File(destFile);
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(arr);
            ObjectInput in = new ObjectInputStream(bis);
            MetadataFile metadataFile= (MetadataFile) in.readObject();
            SecretKey currentKey = token.getGroupMetaData().get(group).getCurrentKey();
            int currentKeyVersion = token.getGroupMetaData().get(group).getKeyIndex();
            SecretKey key = CryptographicFunctions.deriveKey(currentKey, currentKeyVersion, metadataFile.getHashVersion());
            Cipher cipher = CryptographicFunctions.createDecryptionCipher(key, new IvParameterSpec(metadataFile.getIV()));
            byte[] data = cipher.doFinal(metadataFile.getCiphertext());
            Files.write(fi.toPath(), data);
            return true;
        } catch (IOException | ClassNotFoundException ex) {
            System.out.println(ex);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        return sendMessageObject("LFILES", new Object[]{token});
    }

    public boolean upload(String sourceFile, String destFile, String group, UserToken token) {

        if (destFile.charAt(0) != '/') {
            destFile = "/" + destFile;
        }

        File fi = new File(sourceFile);

        FileInputStream fis = null;

        try {
            fis = new FileInputStream(fi);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        byte[] inputBytes = new byte[(int) fi.length()];
        try {
            if (fis != null) {
                fis.read(inputBytes);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        IvParameterSpec iv = CryptographicFunctions.generateIV();
        Cipher cipher = null;
        try {
            cipher = CryptographicFunctions.createEncryptionCipher(token.getGroupMetaData().get(group).getCurrentKey(), iv);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        try {
            byte[] outputBytes = cipher.doFinal(inputBytes);
            MetadataFile outputFile = new MetadataFile(iv, token.getGroupMetaData().get(group).getKeyIndex(), outputBytes);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(outputFile);
            out.flush();
            byte[] yourBytes = bos.toByteArray();

            return sendMessage("UPLOADF", new Object[]{group, destFile, yourBytes, token});
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }

        return false;
    }

}
