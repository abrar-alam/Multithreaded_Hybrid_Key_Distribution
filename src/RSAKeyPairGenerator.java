package project;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPrivateKeyString() {
        return Base64.getEncoder().encodeToString(this.getPrivateKey().getEncoded());
    }

    public String getPublicKeyString() {
        return Base64.getEncoder().encodeToString(this.getPublicKey().getEncoded());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        RSAKeyPairGenerator keyPairGenerator2 = new RSAKeyPairGenerator();
        RSAKeyPairGenerator keyPairGenerator3 = new RSAKeyPairGenerator();

        // keyPairGenerator.writeToFile("RSA/publicKey",
        // keyPairGenerator.getPublicKey().getEncoded());
        // keyPairGenerator.writeToFile("RSA/privateKey",
        // keyPairGenerator.getPrivateKey().getEncoded());
        // System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        // System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
        //
        // System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator2.getPublicKey().getEncoded()));
        // System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator2.getPrivateKey().getEncoded()));
        System.out.println(keyPairGenerator2.getPublicKeyString());
        System.out.println(keyPairGenerator2.getPrivateKeyString());
        System.out.println(keyPairGenerator.getPublicKeyString());
        System.out.println(keyPairGenerator.getPrivateKeyString());

        System.out.println(keyPairGenerator3.getPublicKeyString());
        System.out.println(keyPairGenerator3.getPrivateKeyString());
    }
}
