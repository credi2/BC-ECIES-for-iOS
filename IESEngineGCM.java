package cz.o2.smartbox.utility.security;

import org.spongycastle.crypto.BasicAgreement;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DerivationFunction;
import org.spongycastle.crypto.EphemeralKeyPair;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.KeyParser;
import org.spongycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.IESParameters;
import org.spongycastle.crypto.params.IESWithCipherParameters;
import org.spongycastle.crypto.params.KDFParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.Pack;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;


public class IESEngineGCM {
	BasicAgreement agree;
	DerivationFunction kdf;
	BufferedBlockCipher cipher;

	boolean forEncryption;
	CipherParameters privParam, pubParam;
	IESParameters param;

	byte[] V;
	private EphemeralKeyPairGenerator keyPairGenerator;
	private KeyParser keyParser;
	private byte[] IV;

	/**
	 * set up for use with stream mode, where the key derivation function
	 * is used to provide a stream of bytes to xor with the message.
	 *
	 * @param agree the key agreement used as the basis for the encryption
	 * @param kdf   the key derivation function used for byte generation
	 */
	public IESEngineGCM(
			BasicAgreement agree,
			DerivationFunction kdf)
	{
		this.agree = agree;
		this.kdf = kdf;
		this.cipher = null;
	}


	/**
	 * set up for use in conjunction with a block cipher to handle the
	 * message.
	 *
	 * @param agree  the key agreement used as the basis for the encryption
	 * @param kdf    the key derivation function used for byte generation
	 * @param cipher the cipher to used for encrypting the message
	 */
	public IESEngineGCM(
			BasicAgreement agree,
			DerivationFunction kdf,
			BufferedBlockCipher cipher)
	{
		this.agree = agree;
		this.kdf = kdf;
		this.cipher = cipher;
	}

	/**
	 * Initialise the encryptor.
	 *
	 * @param forEncryption whether or not this is encryption/decryption.
	 * @param privParam     our private key parameters
	 * @param pubParam      the recipient's/sender's public key parameters
	 * @param params        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
	 */
	public void init(
			boolean forEncryption,
			CipherParameters privParam,
			CipherParameters pubParam,
			CipherParameters params)
	{
		this.forEncryption = forEncryption;
		this.privParam = privParam;
		this.pubParam = pubParam;
		this.V = new byte[0];

		extractParams(params);
	}

	/**
	 * Initialise the decryptor.
	 *
	 * @param publicKey      the recipient's/sender's public key parameters
	 * @param params         encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
	 * @param ephemeralKeyPairGenerator             the ephemeral key pair generator to use.
	 */
	public void init(AsymmetricKeyParameter publicKey, CipherParameters params, EphemeralKeyPairGenerator ephemeralKeyPairGenerator)
	{
		this.forEncryption = true;
		this.pubParam = publicKey;
		this.keyPairGenerator = ephemeralKeyPairGenerator;

		extractParams(params);
	}

	/**
	 * Initialise the encryptor.
	 *
	 * @param privateKey      the recipient's private key.
	 * @param params          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
	 * @param publicKeyParser the parser for reading the ephemeral public key.
	 */
	public void init(AsymmetricKeyParameter privateKey, CipherParameters params, KeyParser publicKeyParser)
	{
		this.forEncryption = false;
		this.privParam = privateKey;
		this.keyParser = publicKeyParser;

		extractParams(params);
	}

	private void extractParams(CipherParameters params)
	{
		if (params instanceof ParametersWithIV)
		{
			this.IV = ((ParametersWithIV)params).getIV();
			this.param = (IESParameters)((ParametersWithIV)params).getParameters();
		}
		else
		{
			this.IV = null;
			this.param = (IESParameters)params;
		}
	}

	public BufferedBlockCipher getCipher()
	{
		return cipher;
	}

	private byte[] encryptBlock(
			byte[] in,
			int inOff,
			int inLen)
			throws InvalidCipherTextException
	{
		byte[] C = null, K = null, K1 = null, K2 = null;
		int len;

		if (cipher == null)
		{
			// Streaming mode.
			K1 = new byte[inLen];
			K2 = new byte[param.getMacKeySize() / 8];
			K = new byte[K1.length + K2.length];

			kdf.generateBytes(K, 0, K.length);

			if (V.length != 0)
			{
				System.arraycopy(K, 0, K2, 0, K2.length);
				System.arraycopy(K, K2.length, K1, 0, K1.length);
			}
			else
			{
				System.arraycopy(K, 0, K1, 0, K1.length);
				System.arraycopy(K, inLen, K2, 0, K2.length);
			}

			C = new byte[inLen];

			for (int i = 0; i != inLen; i++)
			{
				C[i] = (byte)(in[inOff + i] ^ K1[i]);
			}
			len = inLen;
		}
		else
		{
			// Block cipher mode.
			K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
			K2 = new byte[param.getMacKeySize() / 8];
			K = new byte[K1.length + K2.length];

			kdf.generateBytes(K, 0, K.length);
			System.arraycopy(K, 0, K1, 0, K1.length);
			System.arraycopy(K, K1.length, K2, 0, K2.length);

			// If iv provided use it to initialise the cipher
			if (IV != null)
			{
				cipher.init(true, new ParametersWithIV(new KeyParameter(K1), IV));
			}
			else
			{
				cipher.init(true, new KeyParameter(K1));
			}

			C = new byte[cipher.getOutputSize(inLen)];
			len = cipher.processBytes(in, inOff, inLen, C, 0);
			len += cipher.doFinal(C, len);
		}


		// Convert the length of the encoding vector into a byte array.
		byte[] P2 = param.getEncodingV();
		byte[] L2 = null;
		if (V.length != 0)
		{
			L2 = getLengthTag(P2);
		}


		// Output the triple (V,C,T).
		byte[] Output = new byte[V.length + len];
		System.arraycopy(V, 0, Output, 0, V.length);
		System.arraycopy(C, 0, Output, V.length, len);
		return Output;
	}

	private byte[] decryptBlock(
			byte[] in_enc,
			int inOff,
			int inLen)
			throws InvalidCipherTextException
	{
		byte[] M = null, K = null, K1 = null, K2 = null;
		int len;

		// Ensure that the length of the input is greater than the MAC in bytes
		if (inLen < V.length)
		{
			throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");
		}

		if (cipher == null)
		{
			// Streaming mode.
			K1 = new byte[inLen - V.length];
			K2 = new byte[param.getMacKeySize() / 8];
			K = new byte[K1.length + K2.length];

			kdf.generateBytes(K, 0, K.length);

			if (V.length != 0)
			{
				System.arraycopy(K, 0, K2, 0, K2.length);
				System.arraycopy(K, K2.length, K1, 0, K1.length);
			}
			else
			{
				System.arraycopy(K, 0, K1, 0, K1.length);
				System.arraycopy(K, K1.length, K2, 0, K2.length);
			}

			M = new byte[K1.length];

			for (int i = 0; i != K1.length; i++)
			{
				M[i] = (byte)(in_enc[inOff + V.length + i] ^ K1[i]);
			}

			len = K1.length;
		}
		else
		{
			// Block cipher mode.
			K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
			K2 = new byte[param.getMacKeySize() / 8];
			K = new byte[K1.length + K2.length];

			kdf.generateBytes(K, 0, K.length);
			System.arraycopy(K, 0, K1, 0, K1.length);
			System.arraycopy(K, K1.length, K2, 0, K2.length);

			// If IV provide use it to initialize the cipher
			if (IV != null)
			{
				cipher.init(false, new ParametersWithIV(new KeyParameter(K1), IV));
			}
			else
			{
				cipher.init(false, new KeyParameter(K1));
			}

			M = new byte[cipher.getOutputSize(inLen - V.length)];
			len = cipher.processBytes(in_enc, inOff + V.length, inLen - V.length, M, 0);
			len += cipher.doFinal(M, len);
		}

		// Output the message.
		return Arrays.copyOfRange(M, 0, len);
	}


	public byte[] processBlock(
			byte[] in,
			int inOff,
			int inLen)
			throws InvalidCipherTextException
	{
		if (forEncryption)
		{
			if (keyPairGenerator != null)
			{
				EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

				this.privParam = ephKeyPair.getKeyPair().getPrivate();
				this.V = ephKeyPair.getEncodedPublicKey();
			}
		}
		else
		{
			if (keyParser != null)
			{
				ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);

				try
				{
					this.pubParam = keyParser.readKey(bIn);
				}
				catch (IOException e)
				{
					throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
				}

				int encLength = (inLen - bIn.available());
				this.V = Arrays.copyOfRange(in, inOff, inOff + encLength);
			}
		}

		// Compute the common value and convert to byte array.
		agree.init(privParam);
		BigInteger z = agree.calculateAgreement(pubParam);
		byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);


		try
		{
			// Initialise the KDF.
			KDFParameters kdfParam = new KDFParameters(Z, V);
			kdf.init(kdfParam);

			return forEncryption
					? encryptBlock(in, inOff, inLen)
					: decryptBlock(in, inOff, inLen);
		}
		finally
		{
			Arrays.fill(Z, (byte)0);
		}
	}

	// as described in Shroup's paper and P1363a
	protected byte[] getLengthTag(byte[] p2)
	{
		byte[] L2 = new byte[8];
		if (p2 != null)
		{
			Pack.longToBigEndian(p2.length * 8L, L2, 0);
		}
		return L2;
	}
}
