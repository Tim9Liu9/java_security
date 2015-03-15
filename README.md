# java_security

### JAVA安全实现三种方式：
    1.JDK 2.Commons Codec 3.Bouncy Castle

====
#### 一。非对称加密算法：com.timliu.security.asymmetric_encryption
    1.DH 2.RSA 3.ElGamal

####  二。Base64：com.timliu.security.base64
    1.JDK实现 2.common codes实现 3.bouncy castle实现

####  三。消息摘要算法：com.timliu.security.message_digest
    1.MD5 2.SHA 3.MAC

####  四。数字签名:JDK实现  com.timliu.security.signature
    1.RSA 2.DSA 3.ECDSA

####  五。对称加密算法：com.timliu.security.symmetric_encryption
    1.3DES 2.AES 3.PBE
    
 
    
====
####   非对称加密算法中“ElGamal” ，的异常问题：
    对于：“Illegal key size or default parameters”异常，是因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）做了相应限制。因此存在一些问题.
Java 6 无政策限制文件：[java官方下载](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html) 本 jce_policy-6.zip 包已经下载到本项目的ext目录下。

Java 7 无政策限制文件：[java官方下载](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html) 本 UnlimitedJCEPolicyJDK7.zip 包已经下载到本项目的ext目录下。
    
    我的macbook 10.10.2安装的是java7：
    到：/Library/Java/JavaVirtualMachines/jdk1.7.0_71.jdk/Contents/Home/jre/lib/security 目录下，对应覆盖local_policy.jar和US_export_policy.jar两个文件。
    
    windows的系统可能需要如下操作：
    切换到%JDK_Home%\jre\lib\security目录下，对应覆盖local_policy.jar和US_export_policy.jar两个文件。同时，你可能有必要在%JRE_Home%\lib\security目录下，也需要对应覆盖这两个文件。
