package com.example.protectapass.Models;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Entity(tableName = "passwords")
public class Password implements Serializable {
    @PrimaryKey(autoGenerate = true)
    int ID;

    @ColumnInfo(name = "websiteName")
    String websiteName = "";

    @ColumnInfo(name = "username")
    String username = "";
    String password = "";

    @ColumnInfo(name = "encryptPass")
    String encryptPass = "";

    @ColumnInfo(name = "passStrength")
    String passwordStrength = "";

    @ColumnInfo(name = "favorite")
    boolean favorite = false;

    private String salt = "";

    private SecretKey encryptKey = null;

    private IvParameterSpec iv = null;

    // NO CHANGE NEEDED
    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getWebsiteName() {
        return websiteName;
    }

    public void setWebsiteName(String websiteName) {
        this.websiteName = websiteName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    //

    private String getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }
    public String decryptPassword() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.encryptKey, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(this.encryptPass));
        String temp = new String(plainText);
        return temp.substring(0, salt.length());

    }

    public void encryptPassword(String password) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PCS5Padding");
        this.encryptKey = generateKey(256);
        IvParameterSpec iv = generateIv();
        this.salt = getSalt();
        cipher.init(Cipher.ENCRYPT_MODE, this.encryptKey, iv);
        byte[] cipherText = cipher.doFinal((password + salt).getBytes());
        this.encryptPass = Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public String getPasswordStrength() {
        return passwordStrength;
    }

    public void setPasswordStrength(String passwordStrength) {
        this.passwordStrength = passwordStrength;
    }

    // NO CHANGE NEEDED
    public boolean isFavorite() {
        return favorite;
    }

    public void setFavorite(boolean favorite) {
        this.favorite = favorite;
    }


}
