package com.flexipgroup;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
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
 * Implement the encrypt() and decrypt() methods on this utility class
 *
 */

public class Encryptor
{
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
    public Encryptor (String password, String inFilePath, String outFilePath)
    {
        this.mPassword = password;
        this.inFilePath = inFilePath;
        this.outFilePath = outFilePath;
    }

    /**
     * return the generated salt for this object
     * @return
     */
    public byte [] getSalt ()
    {
        return (mSalt);
    }

    /**
     * return the initialization vector created from setupEncryption
     * @return
     */
    public byte [] getInitVec ()
    {
        return (mInitVec);
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
     * this must be called after creating the initial Crypto object. It creates a salt of SALT_LEN bytes
     * and generates the salt bytes using secureRandom().  The encryption secret key is created 
     * along with the initialization vectory. The member variable mEcipher is created to be used
     * by the class later on when either creating a CipherOutputStream, or encrypting a buffer
     * to be written to disk.
     *  
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidParameterSpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws IOException 
     */
    public void encrypt () throws NoSuchAlgorithmException, 
                                                           InvalidKeySpecException, 
                                                           NoSuchPaddingException, 
                                                           InvalidParameterSpecException, 
                                                           IllegalBlockSizeException, 
                                                           BadPaddingException, 
                                                           InvalidKeyException, IOException
    {
        SecretKeyFactory factory = null;
        SecretKey tmp = null;

        // crate secureRandom salt and store  as member var for later use
         mSalt = new byte [SALT_LEN];
        SecureRandom rnd = new SecureRandom ();
        rnd.nextBytes (mSalt);
        Db ("generated salt :" + Hex.encodeHexString (mSalt));

        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        /* Derive the key, given password and salt. 
         * 
         * in order to do 256 bit crypto, you have to muck with the files for Java's "unlimted security"
         * The end user must also install them (not compiled in) so beware. 
         * see here:  http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
         * 
         */
        byte[] encodedKey     = Base64.getDecoder().decode(mPassword);
        KeySpec spec = new PBEKeySpec (new String(encodedKey).toCharArray (), mSalt, ITERATIONS, KEYLEN_BITS);
        tmp = factory.generateSecret (spec);
        SecretKey secret = new SecretKeySpec (tmp.getEncoded(), "AES");

        /* Create the Encryption cipher object and store as a member variable
         */
        mEcipher = Cipher.getInstance ("AES/CBC/PKCS5Padding");
        mEcipher.init (Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = mEcipher.getParameters ();

        // get the initialization vector and store as member var 
        mInitVec = params.getParameterSpec (IvParameterSpec.class).getIV();

        Db ("mInitVec is :" + Hex.encodeHexString (mInitVec));
        
        WriteEncryptedFile();
    }




    /**
     * This is where we write out the actual encrypted data to disk using the Cipher created in setupEncrypt().
     * Pass two file objects representing the actual input (cleartext) and output file to be encrypted.
     * 
     * there may be a way to write a cleartext header to the encrypted file containing the salt, but I ran
     * into uncertain problems with that. 
     *  
     * @param input - the cleartext file to be encrypted
     * @param output - the encrypted data file
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void WriteEncryptedFile () throws 
                                                                                          IOException, 
                                                                                          IllegalBlockSizeException, 
                                                                                          BadPaddingException
    {
    	File input = new File(inFilePath);
    	File output = new File(outFilePath);
        FileInputStream fin;
        FileOutputStream fout;
        long totalread = 0;
        int nread = 0;
        byte [] inbuf = new byte [MAX_FILE_BUF];
        
        fout = new FileOutputStream (output);
        fout.write(Hex.encodeHexString(mInitVec).getBytes());
        fout.write(Hex.encodeHexString(mSalt).getBytes());
        System.out.println(input.getAbsolutePath().substring(input.getAbsolutePath().lastIndexOf(".")+1));
        
        //System.out.println(input.getAbsolutePath().lastIndexOf(".")+1);

        System.out.println("Write the nInitVen to stdout: " + Hex.encodeHexString(mInitVec));
        
        fin = new FileInputStream (input);

        while ((nread = fin.read (inbuf)) > 0 )
        {
            Db ("read " + nread + " bytes");
            totalread += nread;

            // create a buffer to write with the exact number of bytes read. Otherwise a short read fills inbuf with 0x0
            // and results in full blocks of MAX_FILE_BUF being written. 
            byte [] trimbuf = new byte [nread];
            for (int i = 0; i < nread; i++)
                trimbuf[i] = inbuf[i];

            // encrypt the buffer using the cipher obtained previosly
            byte [] tmp = mEcipher.update (trimbuf);

            // I don't think this should happen, but just in case..
            
            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + mInitVec.length + tmp.length);
            byteBuffer.put((byte) mInitVec.length);
            byteBuffer.put(mInitVec);
            byteBuffer.put(tmp);
            //return byteBuffer.array();
            
            if (tmp != null)
                fout.write (tmp);
        }
        
        

        // finalize the encryption since we've done it in blocks of MAX_FILE_BUF
        byte [] finalbuf = mEcipher.doFinal ();
        if (finalbuf != null)
            fout.write (finalbuf);
        
        //fout.write(mInitVec, (int)totalread, mInitVec.length);

        fout.flush();
        fin.close();
        fout.close();

        Db ("wrote " + totalread + " encrypted bytes");
    }

}

