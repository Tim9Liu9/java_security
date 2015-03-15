package com.timliu.security.asymmetric_encryption;


import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * 非对称加密算法ElGamal算法组件
 * 非对称算法一般是用来传送对称加密算法的密钥来使用的。相对于RSA算法，这个算法只支持私钥加密公钥解密
 * @author kongqz
 * */
public class ElGamalTest2 {
	//非对称密钥算法
	public static final String KEY_ALGORITHM="ElGamal";
	
	
	/**
	 * 密钥长度，DH算法的默认密钥长度是1024
	 * 密钥长度必须是8的倍数，在160到16384位之间
	 * */
	private static final int KEY_SIZE=256;
	//公钥
	private static final String PUBLIC_KEY="ElGamalPublicKey";
	
	//私钥
	private static final String PRIVATE_KEY="ElGamalPrivateKey";
	
	/**
	 * 初始化密钥对
	 * @return Map 甲方密钥的Map
	 * */
	public static Map<String,Object> initKey() throws Exception{
		//加入对BouncyCastle支持
		Security.addProvider(new BouncyCastleProvider());
		AlgorithmParameterGenerator apg=AlgorithmParameterGenerator.getInstance(KEY_ALGORITHM);
		//初始化参数生成器
		apg.init(KEY_SIZE);
		//生成算法参数
		AlgorithmParameters params=apg.generateParameters();
		//构建参数材料
		DHParameterSpec elParams=(DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
		
		//实例化密钥生成器
		KeyPairGenerator kpg=KeyPairGenerator.getInstance(KEY_ALGORITHM) ;
		
		//初始化密钥对生成器
		kpg.initialize(elParams,new SecureRandom());
		
		KeyPair keyPair=kpg.generateKeyPair();
		//甲方公钥
		PublicKey publicKey= keyPair.getPublic();
		//甲方私钥
		PrivateKey privateKey= keyPair.getPrivate();
		//将密钥存储在map中
		Map<String,Object> keyMap=new HashMap<String,Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
		
	}
	
	
	/**
	 * 公钥加密
	 * @param data待加密数据
	 * @param key 密钥
	 * @return byte[] 加密数据
	 * */
	public static byte[] encryptByPublicKey(byte[] data,byte[] key) throws Exception{
		
		//实例化密钥工厂
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		//初始化公钥
		//密钥材料转换
		X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
		//产生公钥
		PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);
		
		//数据加密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return cipher.doFinal(data);
	}
	/**
	 * 私钥解密
	 * @param data 待解密数据
	 * @param key 密钥
	 * @return byte[] 解密数据
	 * */
	public static byte[] decryptByPrivateKey(byte[] data,byte[] key) throws Exception{
		//取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		//生成私钥
		PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
		//数据解密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 取得私钥
	 * @param keyMap 密钥map
	 * @return byte[] 私钥
	 * */
	public static byte[] getPrivateKey(Map<String,Object> keyMap){
		Key key=(Key)keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	/**
	 * 取得公钥
	 * @param keyMap 密钥map
	 * @return byte[] 公钥
	 * */
	public static byte[] getPublicKey(Map<String,Object> keyMap) throws Exception{
		Key key=(Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		//初始化密钥
		//生成密钥对
		Map<String,Object> keyMap=ElGamalTest2.initKey();
		//公钥
		byte[] publicKey=ElGamalTest2.getPublicKey(keyMap);
		
		//私钥
		byte[] privateKey=ElGamalTest2.getPrivateKey(keyMap);
		System.out.println("公钥：/n"+Base64.encodeBase64String(publicKey));
		System.out.println("私钥：/n"+Base64.encodeBase64String(privateKey));
		
		System.out.println("================密钥对构造完毕,甲方将公钥公布给乙方，开始进行加密数据的传输=============");
		String str="ElGamal密码交换算法";
		System.out.println("/n===========甲方向乙方发送加密数据==============");
		System.out.println("原文:"+str);
		
		//乙方使用公钥对数据进行加密
		byte[] code2=ElGamalTest2.encryptByPublicKey(str.getBytes(), publicKey);
		System.out.println("===========乙方使用公钥对数据进行加密==============");
		System.out.println("加密后的数据："+Base64.encodeBase64String(code2));
		
		
		//甲方使用私钥对数据进行解密
		byte[] decode2=ElGamalTest2.decryptByPrivateKey(code2, privateKey);
		
		System.out.println("甲方解密后的数据："+new String(decode2));
	}
}


