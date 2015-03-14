package com.timliu.security.symmetric_encryption;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESTest 
{
	public static final String src = "aes test";
	public static void main(String[] args) 
	{
		jdkAES();
		bcAES();

	}
	
	// 用jdk实现:
	public static void jdkAES()
	{
		try 
		{
			// 生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");			
			keyGenerator.init(128);
			// 产生密钥
			SecretKey secretKey = keyGenerator.generateKey();
			// 获取密钥
			byte[] keyBytes = secretKey.getEncoded();
			
			
			// KEY转换
			Key key = new SecretKeySpec(keyBytes, "AES");
			
			
			// 加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk aes encrypt:" + Hex.encodeHexString(result));
			
			// 解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			result = cipher.doFinal(result);
			System.out.println("jdk aes decrypt:" + new String(result));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// 用bouncy castle实现:
	public static void bcAES()
	{
		try 
		{
			Security.addProvider(new BouncyCastleProvider());
			
			// 生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");	
			keyGenerator.getProvider();
			keyGenerator.init(128);
			// 产生密钥
			SecretKey secretKey = keyGenerator.generateKey();
			// 获取密钥
			byte[] keyBytes = secretKey.getEncoded();
			
			
			// KEY转换
			Key key = new SecretKeySpec(keyBytes, "AES");
			
			
			// 加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc aes encrypt:" + Hex.encodeHexString(result));
			
			// 解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			result = cipher.doFinal(result);
			System.out.println("bc aes decrypt:" + new String(result));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
