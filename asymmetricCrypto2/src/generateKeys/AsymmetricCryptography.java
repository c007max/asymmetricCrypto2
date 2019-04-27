package generateKeys;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class AsymmetricCryptography {
	private Cipher cipher;

	public byte[] decodeUsingApacheCommons(String hexString) throws DecoderException 
	{
		return Hex.decodeHex(hexString);
	}
	
	public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	public PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		
		String pubKeySTR = new String(Hex.encodeHex(keyBytes));
		System.out.println(pubKeySTR);
		
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public void encryptFile(byte[] input, File output, PublicKey key) 
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	public void decryptFile(byte[] input, File output, PrivateKey key) 
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	private void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException 
	{
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public String encryptText(String msg, PublicKey key) 
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, 
			BadPaddingException, InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}
	
	public String encryptPrivate(String msg, PrivateKey key) 
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, 
			BadPaddingException, InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}
	
	public String decryptText(String msg, PrivateKey key)
			throws InvalidKeyException, UnsupportedEncodingException, 
			IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}
	
	
	public String decryptPublic(String msg, PublicKey key)
			throws InvalidKeyException, UnsupportedEncodingException, 
			IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}
	
	public byte[] getFileInBytes(File f) throws IOException {
		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		
		fis.read(fbytes);
		
		String hexString = Hex.encodeHexString(fbytes);
		System.out.println("\n0090\tfile hex\n" + hexString);
		String asciiString = new String(fbytes);
		System.out.println("\n0095\tfile ascii\n" + asciiString);
		
		fis.close();
		return fbytes;
	}

	public static void main(String[] args) throws Exception 
	{
		AsymmetricCryptography ac = new AsymmetricCryptography();
		PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
		PublicKey publicKey = ac.getPublic("KeyPair/publicKey");
				
		//	00200
		if (new File("KeyPair/text.txt").exists()) 
		{
			ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")), 
				new File("KeyPair/text_encrypted.txt"),publicKey);
			
			String hexString = Hex.encodeHexString(publicKey.getEncoded());
			System.out.println("\n00205\tpublic key in Hex\n" + hexString);
			
			// encrypt with recoded hexString
			
	        byte [] byteARRAY	= Hex.decodeHex (hexString) ;
			ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")), 
					new File("KeyPair/text_encrypted2.txt"),byteARRAY);
			
			ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")),
				new File("KeyPair/text_decrypted.txt"), privateKey);
			
			hexString = Hex.encodeHexString(privateKey.getEncoded());
			System.out.println("\n00210\tprivate key in Hex\n" + hexString);
		} 
//		else 
//		{
//			String msg = "CMP246--My favorite movie for 2018 is Scario2";
//			String encrypted_msg = ac.encryptText(msg, publicKey);
//			String decrypted_msg = ac.decryptText(encrypted_msg, privateKey);
//			System.out.printf("Original Message:%s"
//					+ "\nEncrypted Message:%s"
//					+ "\nDecrypted Message%s"
//					,msg
//					,encrypted_msg
//					,decrypted_msg
//					);		
//		}
		
		//	encrypt message for TS
		
//		String msg = "CMP246--This is an encrypted message for Thomas Sauers";
//		String encrypted_msg = ac.encryptText(msg, publicKeyTS);
//		System.out.printf("Original Message:%s"
//				+ "\nEncrypted Message:%s"
//				,msg
//				,encrypted_msg
//				);	
		
		//	encrypt message for JG		

//		String msg = "CMP246--Nice work on the Public Key, Jonathan Gutierrez";
//		String encrypted_msg = ac.encryptText(msg, publicKeyJG);
//		System.out.printf("Original Message:%s"
//				+ "\nEncrypted Message:%s"
//				,msg
//				,encrypted_msg
//				);	
		
//		String msg = "CMP246--Verification that this message is from J. Lam";
//		String encrypted_msg = ac.encryptPrivate(msg, privateKey);
//		String decrypted_msg = ac.decryptPublic(encrypted_msg, publicKey);
//		System.out.printf("Original Message:%s"
//				+ "\nEncrypted Message:%s"
//				+ "\nDecrypted Message:%s"
//				,msg
//				,encrypted_msg
//				,decrypted_msg
//				);	
	}
}
