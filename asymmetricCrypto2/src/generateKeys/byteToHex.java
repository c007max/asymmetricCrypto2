package generateKeys;


import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

public class byteToHex 
{
	public String encodeUsingApacheCommons(byte[] bytes) 
			throws DecoderException 
	{
		return Hex.encodeHexString(bytes);
	}

	public static byte[] decodeUsingApacheCommons(String hexString) 
			throws DecoderException 
	{
		return Hex.decodeHex(hexString);
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
	
	private static void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException 
	{
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}
	
	public static byte[] getFileInBytes(File f) throws IOException {
		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		
		fis.read(fbytes);
		
		String hexString = Hex.encodeHexString(fbytes);
		System.out.println("file hex:\n" + hexString);

		String asciiString = new String(fbytes);
		System.out.println("file ascii:\n" + asciiString);
		
		fis.close();
		return fbytes;
	}
	
	public static void main(String[] args) throws Exception 
	{
//		File f = new File("KeyPair/publicKey");
//		byte [] byteARRAY = getFileInBytes(f);
//		
//		String pubKeySTR = new String(Hex.encodeHex(byteARRAY));
//		System.out.println("#0050\tpublickey Hex:\n"	+ pubKeySTR);
		
		// Reading file into String using proper character encoding
        
		String fileSTR = new String(Files.readAllBytes(Paths.get("KeyPair/publicKey.txt")), StandardCharsets.UTF_8);
        System.out.println("#0060\tpublickey\n" + fileSTR);
        
        // convert string to byteARRAY
        
        byte [] byteARRAY	= Hex.decodeHex (fileSTR) ;
        
        // write byteARRAY to publicKey file

        FileOutputStream fos	= new FileOutputStream(new File("KeyPair/publicKeyJL"));
        fos.write(byteARRAY);
        fos.close();
        
        // read byteARRAY of publicKey
        
		File f = new File("KeyPair/publicKeyJL");
		byteARRAY = getFileInBytes(f);
		
		String pubKeySTR = new String(Hex.encodeHex(byteARRAY));
		System.out.println("#0070\tpublickeyJG Hex:\n"	+ pubKeySTR);

	}

}

