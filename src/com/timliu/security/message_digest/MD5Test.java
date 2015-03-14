package com.timliu.security.message_digest;

import java.security.MessageDigest;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MD5Test 
{

	public static final String src = "md5 test";
	public static void main(String[] args) 
	{
		jdkMD5();
		jdkMD2();
		
		bcMD4();
		bcMD5();
		
		bc2jdkMD4();
		
		ccMD5();
		ccMD2();

	}
	
	// 用jdk实现:MD5
	public static void jdkMD5()
	{
		try 
		{
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5Bytes = md.digest(src.getBytes());
			System.out.println("JDK MD5:" + Hex.encodeHexString(md5Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// 用jdk实现:MD2
	public static void jdkMD2()
	{
		try 
		{
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md2Bytes = md.digest(src.getBytes());
			System.out.println("JDK MD2:" + Hex.encodeHexString(md2Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	// 用bouncy castle实现:MD5
	public static void bcMD5()
	{
		MD5Digest digest = new MD5Digest();
		digest.update(src.getBytes(),0,src.getBytes().length);
		byte[] md5Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md5Bytes, 0);
		System.out.println("bouncy castle MD5:" + org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes));
		
	}
	

	// 用bouncy castle实现:MD4
	public static void bcMD4()
	{
		MD4Digest digest = new MD4Digest();
		digest.update(src.getBytes(),0,src.getBytes().length);
		byte[] md4Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md4Bytes, 0);
		System.out.println("bouncy castle MD4:" + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
	}
	
	// 用bouncy castle与jdk结合实现:MD4
	public static void bc2jdkMD4()
	{
		try 
		{
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("MD4");
			byte[] md4Bytes = md.digest(src.getBytes());
			System.out.println("bc and JDK MD4:" + Hex.encodeHexString(md4Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// 用common codes实现实现:MD5
	public static void ccMD5()
	{
		System.out.println("common codes MD5:" + DigestUtils.md5Hex(src.getBytes()));
	}
	
	// 用common codes实现实现:MD2
	public static void ccMD2()
	{
		System.out.println("common codes MD2:" + DigestUtils.md2Hex(src.getBytes()));
	}

}
