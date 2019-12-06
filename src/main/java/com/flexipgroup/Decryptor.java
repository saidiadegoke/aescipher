package com.flexipgroup;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;


/**
 * 
 * TODO
 * 
 * This class is takes three parameters for it to work.
 * 1. The AES Secret key
 * 2. The encrypted file path
 * 3. The file path where the decryped file will be written to.
 * This class contains a utility function called decrypt().
 *
 */

public class Decryptor
{
	// Instance variable for the AES Secret Key
    String mPassword = null;
    public final static int SALT_LEN = 8;
    byte [] mInitVec = null;
    byte [] mSalt = null;
    Cipher mEcipher = null;
    Cipher mDecipher = null;
    private final int KEYLEN_BITS = 128; // see notes below where this is used.
    private final int ITERATIONS = 65536;
    private final int MAX_FILE_BUF = 1024;
	private String inFilePath;
	private String outFilePath;

    /**
     * create an object with just the passphrase from the user. Don't do anything else yet 
     * @param password
     */
    public Decryptor (String password, String inFilePath, String outFilePath)
    {
    	// The SecretKey
        this.mPassword = password;
        
        // The location of the encrypted file on the file system
        // E.g C:\\Users\\username\\Desktop\\encryptedfile.xlsx"
        this.inFilePath = inFilePath;
        
        // The location where the file is to be decrypted to on the file system.
        // E.g C:\\Users\\username\\Desktop\\decryptedfile.xlsx"
        this.outFilePath = outFilePath;
        
        Db("InFile: " + inFilePath);
    }

    /**
     * return the generated salt for this object
     * @return
     */
    public byte [] getSalt ()
    { 
        return null;
    }

    /**
     * return the initialization vector created from setupEncryption
     * @return
     */
    public byte [] getInitVec ()
    {
        return null;
    }

    /**
     * debug/print messages
     * @param msg
     */
    private void Db (String msg)
    {
        System.out.println ("** Crypt ** " + msg);
    }

    /**
     * If a file is being decrypted, we need to know the pasword, the salt and the initialization vector (iv). 
     * We have the password from initializing the class. pass the iv and salt here which is
     * obtained when encrypting the file initially.
     *   
     * @param initvec
     * @param salt
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws DecoderException
     * @throws IOException 
     */
    public void decrypt () throws NoSuchAlgorithmException, 
                                                                                       InvalidKeySpecException, 
                                                                                       NoSuchPaddingException, 
                                                                                       InvalidKeyException, 
                                                                                       InvalidAlgorithmParameterException, 
                                                                                       DecoderException, IOException
    {
    	//String initvec;
    	//String salt;
        SecretKeyFactory factory = null;
        SecretKey tmp = null;
        SecretKey secret = null;
        byte[] initvec = new byte[32];
        byte[] salt = new byte[16];
        File input = new File(inFilePath);
    	
    	String ext = outFilePath.substring(outFilePath.lastIndexOf("."));
    	if(ext.contains("aes")) {
    		outFilePath = outFilePath.substring(0, outFilePath.lastIndexOf("."));
    	}
    	
    	File output = new File(outFilePath);
        FileInputStream fin; 
        FileOutputStream fout;
        CipherInputStream cin;
        long totalread = 0;
        int nread = 0;
        byte [] inbuf = new byte [MAX_FILE_BUF];

        fout = new FileOutputStream (output);
        fin = new FileInputStream (input);
        
        

        // Read the initialization vector from the encrypted file
        fin.read(initvec);
        
        // Next read the salt from the encrypted file
        fin.read(salt);

        // since we pass it as a string of input, convert to a actual byte buffer here
        String nsalt = new String(salt);
        if(!nsalt.isEmpty() && nsalt != null ) {
	        mSalt = Hex.decodeHex(nsalt.toCharArray());
	        Db ("got salt " + Hex.encodeHexString(mSalt));
        } else {
        	Db ("got no salt " + nsalt);
        }

        // get initialization vector from passed string
        String niv = new String(initvec);
        if(!niv.isEmpty() && niv != null) {
	        mInitVec = Hex.decodeHex(niv.toCharArray());
	        Db ("got initvector1 :" + Hex.encodeHexString(mInitVec));
        } else {
        	Db("got not iv " + niv);
        }

        /* Derive the key, given password and salt. */
        // in order to do 256 bit crypto, you have to muck with the files for Java's "unlimted security"
        // The end user must also install them (not compiled in) so beware. 
        // see here: 
      // http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] encodedKey     = Base64.getDecoder().decode(mPassword);
        KeySpec spec = new PBEKeySpec(new String(encodedKey).toCharArray(), mSalt, ITERATIONS, KEYLEN_BITS);

        tmp = factory.generateSecret(spec);
        
        //SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        secret = new SecretKeySpec(tmp.getEncoded(), 0, encodedKey.length, "AES");

        /* Decrypt the message, given derived key and initialization vector. */
        mDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        mDecipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(mInitVec));
        
     // creating a decoding stream from the FileInputStream above using the cipher created from setupDecrypt()
        cin = new CipherInputStream (fin, mDecipher);

        while ((nread = cin.read (inbuf)) > 0 )
        {
            Db ("read " + nread + " bytes");
            totalread += nread;

            // create a buffer to write with the exact number of bytes read. Otherwise a short read fills inbuf with 0x0
            byte [] trimbuf = new byte [nread];
            for (int i = 0; i < nread; i++)
                trimbuf[i] = inbuf[i];

            // write out the size-adjusted buffer
            fout.write (trimbuf);
        }

        fout.flush();
        cin.close();
        fin.close ();       
        fout.close();
    }

}

