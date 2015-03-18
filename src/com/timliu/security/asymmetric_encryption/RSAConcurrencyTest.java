package com.timliu.security.asymmetric_encryption;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class RSAConcurrencyTest 
{
	public static final String src = "rsa test";
	
	private static byte[] result;

	public static void main(String[] args) throws Exception 
	{
		RSA();
		
		

	}
	
	// jdk实现：私钥加密、公钥解密： 并发时间测试
	public static void RSA()
	{		
		try 
		{
			long startTimes = System.currentTimeMillis();
			
			
			// 1.初始化发送方密钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			System.out.println("Public Key:" + Base64.encodeBase64String(rsaPublicKey.getEncoded()));
			System.out.println("Private Key:" + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
			
			
			
			
			// 2.公钥加密、私钥解密 ---- 加密
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(src.getBytes());
			System.out.println("公钥加密、私钥解密 ---- 加密:" + Base64.encodeBase64String(result));
			
			long endEncryptTime = System.currentTimeMillis();
			System.out.println("公钥加密、私钥解密 ---- 加密1个时间(单位毫秒):" + (endEncryptTime - startTimes));
			
			int decryptTimes = 200000;  // 并发解密的个数
			//创建一个可重用固定线程数的线程池
	        ExecutorService pool =  Executors.newCachedThreadPool(); // Executors.newFixedThreadPool(1000);
	        
			for(int i=0; i<decryptTimes;i++)
			{
				pool.execute(new Thread(new Runnable() {
					
					@Override
					public void run() {
						try {
							// 3.私钥解密、公钥加密 ---- 解密
							PKCS8EncodedKeySpec pkcs8EncodedKeySpec2 = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
							KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
							
							PrivateKey privateKey2 = keyFactory2.generatePrivate(pkcs8EncodedKeySpec2);
							Cipher cipher2 = Cipher.getInstance("RSA");
							cipher2.init(Cipher.DECRYPT_MODE, privateKey2);
							byte[] result2 = cipher2.doFinal(result);
//							System.out.println("公钥加密、私钥解密 ---- 解密:" + new String(result2));
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}));
			  
			}
			
			pool.shutdown();
			
			while (true) {  
	            if (pool.isTerminated()) {  
	                System.out.println("结束了！"); 
	                long endDencryptTime = System.currentTimeMillis() ;
	                long totalTimes = (endDencryptTime - endEncryptTime) / 1000;
	                System.out.println("公钥加密、私钥解密 ---- 并发：" + decryptTimes + "个解密时间(单位秒):" + totalTimes);
	                break;  
	            }  
	            Thread.sleep(200);  
	        }
			
			
		} catch (Exception e) {
			
			e.printStackTrace();
		}
		
	}
	
	
}
