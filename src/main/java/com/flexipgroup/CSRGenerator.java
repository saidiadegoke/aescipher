package com.flexipgroup;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public class CSRGenerator {
	private final String ARG = "RSA";
	private final int KEY_SIZE = 2048;
	private final String COMMON_NAME = "corporatepayments.ubagroup.com";
	private final String ORGANIZATIONAL_UNIT = "Product Delivery & Tech Support";
	private final String ORGANIZATION = "United Bank for Africa PLC";
	private final String LOCATION = "Lagos Island";
	private final String STATE = "State";
	private final String COUNTRY = "NG";
	
	public void generate() {
		KeyPair pair = generateKeyPair(ARG, KEY_SIZE);
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
		    new X500Principal(String.format("CN=%1$s, OU=%2$s, O=%3$s, L=%4$s, S=%5$s, C=%6$s", 
		    		COMMON_NAME,
		    		ORGANIZATIONAL_UNIT,
		    		ORGANIZATION,
		    		LOCATION,
		    		STATE,
		    		COUNTRY
		    	)), pair.getPublic());

		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer;
		try {
			signer = csBuilder.build(pair.getPrivate());
			PKCS10CertificationRequest csr = p10Builder.build(signer);
			
			toPEMFile(csr);
            
            System.out.println(csrPEMformat(csr));
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
     * Generate the desired keypair
     * 
     * @param alg
     * @param keySize
     * @return
     */
    KeyPair generateKeyPair(String alg, int keySize) {
        try{
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance(alg);
             
            keyPairGenerator.initialize(keySize);
             
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
         
        return null;
    }
    
    /**
     * Serialize Certificate in PEM format
     */
    public static String toPEMformat(X509Certificate certificate) {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        try {
            pemWriter.writeObject(certificate);
            pemWriter.close();

            return sw.toString();

        } catch (IOException x) {
            throw new RuntimeException("Failed to serialize certificate", x);
        }
    }
    
    public void toPEMFile(PKCS10CertificationRequest csr) {
    	PemObject pemObject;
		try {
			pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
	    	FileWriter fileWriter = new FileWriter(new File("tmp/keys/csr.pem"));
	    	JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
			pemWriter.writeObject(pemObject);
			pemWriter.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    /**
     * Serialize Certificate in PEM format
     */
    public static String csrPEMformat(PKCS10CertificationRequest csr) {
    	PemObject pemObject;
		try {
			pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
	    	StringWriter str = new StringWriter();
	    	JcaPEMWriter pemWriter = new JcaPEMWriter(str);
			pemWriter.writeObject(pemObject);
			pemWriter.close();
	    	str.close();
	    	return str.toString();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
    	
    }

}
