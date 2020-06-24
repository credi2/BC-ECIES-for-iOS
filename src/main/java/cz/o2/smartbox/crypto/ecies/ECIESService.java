package cz.o2.smartbox.crypto.ecies;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ECIESService {

    public static byte[] encrypt(byte[] plainTextBytes, byte[] publicKeyBytes, String curveName) throws Exception {

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), publicKeyBytes);
        java.security.spec.ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

        org.bouncycastle.jce.spec.IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, null);
        IESCipherGCM cipher = new IESCipherGCM(
                new IESEngineGCM(
                        new ECDHBasicAgreement(),
                        new KDF2BytesGenerator(new SHA256Digest()),
                        new AESGCMBlockCipher()), 16);

        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, params, new SecureRandom());

        byte[] cipherResult = cipher.engineDoFinal(plainTextBytes, 0, plainTextBytes.length);
        return cipherResult;
    }

    public static String decrypt(String ciphertext, byte[] privateKeyBytes) throws Exception {

        java.security.spec.PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(encodedKeySpec);

        byte[] inputBytes = Base64.decode(ciphertext);

        IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, null);
        IESCipherGCM cipher = new IESCipherGCM(
                new IESEngineGCM(
                        new ECDHBasicAgreement(),
                        new KDF2BytesGenerator(new SHA256Digest()),
                        new AESGCMBlockCipher()), 16);

        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, params, new SecureRandom());

        byte[] cipherResult = cipher.engineDoFinal(inputBytes, 0, inputBytes.length);
        return new String(cipherResult);

    }

}
