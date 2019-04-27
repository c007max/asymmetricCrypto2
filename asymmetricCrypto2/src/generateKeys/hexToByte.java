package generateKeys;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class hexToByte 
{
	public String encodeUsingApacheCommons(byte[] bytes) 
			throws DecoderException 
	{
		return Hex.encodeHexString(bytes);
	}
	
	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		
		String pubKeySTR = new String(Hex.encodeHex(keyBytes));
		System.out.println(pubKeySTR);
		
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
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
		System.out.println("#0070\tpublickeyJL Hex:\n"	+ pubKeySTR);

	}

}

