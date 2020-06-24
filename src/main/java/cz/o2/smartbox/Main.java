package cz.o2.smartbox;

import cz.o2.smartbox.crypto.ecies.ECIESService;
import org.bouncycastle.util.encoders.Base64;

public class Main {

    private static String PEER_PUBLIC_KEY = "BMgQBKP98y4zREWNUn+j1f5aiM8kA2h0Hy055H/vLtDIDM7b7AQGDsUrIPbqQUSDPveQCN4/OZjUC8Ji/7oXQVs=\n";

    public static void main( String[] args ) {
        Main m = new Main();
    }

    public Main () {
        try {
            /*
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            g.initialize(ecSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) pair.getPublic();

            System.out.println("======== Generated public key:  " + Base64.toBase64String(publicKey.getEncoded()));
            System.out.println("======== Generated private key: " + Base64.toBase64String(privateKey.getEncoded()));
            */

            // This produces ciphertext that can be decrypted by calling
            // `SecKeyCreateDecryptedData` on iOS
            String plaintext = "test";
            System.out.println("======== Encrypting message:    " + plaintext);
            String encryptedPlaintext = testEncrypt(plaintext, PEER_PUBLIC_KEY);
            System.out.println("======== Ciphertext:            " + encryptedPlaintext);

            // This ciphertext was produced by Apple's `SecKeyCreateDecryptedData`
            // method using the following public key data:
            // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+E1qHuq3h1Z/wlZhV9eJMLyZTlm6hFR/A5grmnMNCkN7kzCQcWfgaa0vw24mFk20AyF6G6EX/lxyxZZjFQWaJA==
            String ciphertext = "BAfx2IcjzCaggrAF76ztZDAJzaEfJFGgSyVsqt3MsXmxhRtiPVHRkh3VIjeUB+fPSyoI5xJ0+Bjq4uQgJ1GtkFx/zLiR/LSf/UBgzkkPPDBXXdQDKjcS";
            String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgCIkUy+DMVJDPhHQwS1lCrT/72qcz0vFWinZf3Gl0g5OgCgYIKoZIzj0DAQehRANCAAT4TWoe6reHVn/CVmFX14kwvJlOWbqEVH8DmCuacw0KQ3uTMJBxZ+BprS/DbiYWTbQDIXoboRf+XHLFlmMVBZok";
            System.out.println("======== Decrypting message:    " + ciphertext);
            String decryptedCiphertext = testDecrypt(ciphertext, privateKey);
            System.out.println("======== Plaintext:             " + decryptedCiphertext);

        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public String testEncrypt (String plaintext, String peerPublicKey) throws Exception {
        byte[] publicKey = Base64.decode(peerPublicKey);
        return ECIESService.encrypt(plaintext, publicKey, "secp256r1");
    }

    public String testDecrypt (String ciphertext, String ownPrivateKey) throws Exception {
        byte[] privateKey = Base64.decode(ownPrivateKey);
        return ECIESService.decrypt(ciphertext, privateKey);
    }

}
