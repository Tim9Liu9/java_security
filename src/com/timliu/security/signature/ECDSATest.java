package com.timliu.security.signature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Hex;

import com.sun.xml.internal.fastinfoset.algorithm.HexadecimalEncodingAlgorithm;



public class ECDSATest 
{
	public static final String src = "ECDSA security is security";
	
	public static void main(String[] args) 
	{
		jdkECDSA();

	}
	
	/**
	 * 
	 * @author timliu
	 * 说明： 用java的jdk里面相关方法实现ECDSA的签名及签名验证,要jdk7.x以上，ECDSA：椭圆曲线数字签名算法
	 */
	public static void jdkECDSA()
	{
		try {
			// 1.初始化密钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
			keyPairGenerator.initialize(256);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
			ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
			
			// 2.进行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature = Signature.getInstance("SHA1withECDSA");
			signature.initSign(privateKey);
			signature.update(src.getBytes());
			byte[] result = signature.sign();
			System.out.println("jdk ecdsa sign:" + Hex.encodeHexString(result) );
			
			// 3.验证签名
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
			keyFactory = KeyFactory.getInstance("EC");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			signature = Signature.getInstance("SHA1withECDSA");
			signature.initVerify(publicKey);
			signature.update(src.getBytes());
			boolean bool = signature.verify(result);
			System.out.println("jdk ecdsa verify:" + bool);
		} catch (Exception e) {
			System.out.println(e.toString());
		}
		
	}

}
