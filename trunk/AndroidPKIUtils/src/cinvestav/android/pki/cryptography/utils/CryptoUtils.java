/**
 *  Created on  : 16/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import org.spongycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.MD2Digest;
import org.spongycastle.crypto.digests.MD4Digest;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.RIPEMD128Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.RIPEMD256Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PKCS8Generator;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class CryptoUtils {

	static {
		Security.addProvider(new BouncyCastleProvider());
		try {
			jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {

		}
	}
	public static final String PROVIDER = "SC";

	public static final String ENCODER_BASE64 = "ENCODER_BASE64";
	public static final String ENCODER_HEX = "ENCODER_HEX";

	public static final String ENCODING_DER = "DER";
	public static final String ENCODING_PEM = "PEM";

	public static SecureRandom secureRandom = new SecureRandom(
			SecureRandom.getSeed(512));

	public static JcaX509ExtensionUtils jcaX509ExtensionUtils;

	public static final String DIGEST_FUNCTION_RIPEMD128 = "RIPEMD128";
	public static final String DIGEST_FUNCTION_RIPEMD160 = "RIPEMD160";
	public static final String DIGEST_FUNCTION_RIPEMD256 = "RIPEMD256";

	public static final String DIGEST_FUNCTION_SHA_1 = "SHA-1";
	public static final String DIGEST_FUNCTION_SHA_224 = "SHA-224";
	public static final String DIGEST_FUNCTION_SHA_256 = "SHA-256";
	public static final String DIGEST_FUNCTION_SHA_384 = "SHA-384";
	public static final String DIGEST_FUNCTION_SHA_512 = "SHA-512";

	public static final String DIGEST_FUNCTION_MD2 = "MD2";
	public static final String DIGEST_FUNCTION_MD4 = "MD4";
	public static final String DIGEST_FUNCTION_MD5 = "MD5";

	/**
	 * Creates an instance of a Digest depending on the name of it
	 * 
	 * @param digestName
	 *            Name of the desired Digest
	 * @return An instance of a Digest object
	 * @throws CryptoUtilsException
	 *             If the name does not correspond to a supported digest
	 *             algorithm
	 */
	public static Digest selectDigest(String digestName)
			throws CryptoUtilsException {
		// Check the digest Name and create a Digest object
		if (digestName.endsWith(DIGEST_FUNCTION_MD2)) {
			return new MD2Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_MD4)) {
			return new MD4Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_MD5)) {
			return new MD5Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_RIPEMD128)) {
			return new RIPEMD128Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_RIPEMD160)) {
			return new RIPEMD160Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_RIPEMD256)) {
			return new RIPEMD256Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_SHA_1)) {
			return new SHA1Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_SHA_224)) {
			return new SHA224Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_SHA_256)) {
			return new SHA256Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_SHA_384)) {
			return new SHA384Digest();
		}
		if (digestName.endsWith(DIGEST_FUNCTION_SHA_512)) {
			return new SHA512Digest();
		}

		throw new CryptoUtilsException("Selected Digest [" + digestName
				+ "] is not supported");
	}

	/**
	 * Supported Encryption algorithms for PEM encoded keys
	 */
	public static final String AES_128_CBC = "AES-128-CBC";
	public static final String AES_192_CBC = "AES-192-CBC";
	public static final String AES_256_CBC = "AES-256-CBC";
	public static final String DES3_CBC = "DES-EDE3-CBC";
	public static final String PBE_SHA1_RC4_128 = "PBE-SHA1-RC4-128";
	public static final String PBE_SHA1_RC4_40 = "PBE-SHA1-RC4-40";
	public static final String PBE_SHA1_3DES = "PBE-SHA1-3DES";
	public static final String PBE_SHA1_2DES = "PBE-SHA1-2DES";
	public static final String PBE_SHA1_RC2_128 = "PBE-SHA1-RC2-128";
	public static final String PBE_SHA1_RC2_40 = "PBE-SHA1-RC2-40";

	/**
	 * Select algorithm ID in base on the name and encoding
	 * 
	 * @param algorithm
	 * @param encoding
	 * @return
	 * @throws CryptoUtilsException
	 */
	public static String selectAlgorithmID(String algorithm, String encoding)
			throws CryptoUtilsException {
		if (encoding.equalsIgnoreCase("DER")) {
			String alg;
			String blockMode = "CBC";
			String padding = "PKCS5Padding";

			// Figure out block mode and padding.
			if (algorithm.endsWith("-CFB")) {
				blockMode = "CFB";
				padding = "NoPadding";
			}
			if (algorithm.endsWith("-ECB") || "DES-EDE".equals(algorithm)
					|| "DES-EDE3".equals(algorithm)) {
				// ECB is actually the default (though seldom used) when OpenSSL
				// uses DES-EDE (des2) or DES-EDE3 (des3).
				blockMode = "ECB";
			}
			if (algorithm.endsWith("-OFB")) {
				blockMode = "OFB";
				padding = "NoPadding";
			}

			// Figure out algorithm and key size.
			if (algorithm.startsWith("DES-EDE")) {
				alg = "DESede";
				// "DES-EDE" is actually des2 in OpenSSL-speak!
				// "DES-EDE3" is des3.
			} else if (algorithm.startsWith("DES-")) {
				alg = "DES";
			} else if (algorithm.startsWith("BF-")) {
				alg = "Blowfish";
			} else if (algorithm.startsWith("RC2-")) {
				alg = "RC2";
				/*
				 * int keyBits = 128; if (algorithm.startsWith("RC2-40-")) {
				 * keyBits = 40; } else if (algorithm.startsWith("RC2-64-")) {
				 * keyBits = 64; }
				 */
			} else if (algorithm.startsWith("AES-")) {
				alg = "AES";
			} else {
				throw new CryptoUtilsException(
						"unknown encryption with private key");
			}

			return alg + "/" + blockMode + "/" + padding;

		} else if (encoding.equalsIgnoreCase("PEM")) {
			if (algorithm.equalsIgnoreCase(AES_128_CBC)) {
				return PKCS8Generator.AES_128_CBC;
			}
			if (algorithm.equalsIgnoreCase(AES_192_CBC)) {
				return PKCS8Generator.AES_192_CBC;
			}
			if (algorithm.equalsIgnoreCase(AES_256_CBC)) {
				return PKCS8Generator.AES_256_CBC;
			}
			if (algorithm.equalsIgnoreCase(DES3_CBC)) {
				return PKCS8Generator.DES3_CBC;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_RC4_128)) {
				return PKCS8Generator.PBE_SHA1_RC4_128;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_RC4_40)) {
				return PKCS8Generator.PBE_SHA1_RC4_40;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_3DES)) {
				return PKCS8Generator.PBE_SHA1_3DES;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_2DES)) {
				return PKCS8Generator.PBE_SHA1_2DES;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_RC2_128)) {
				return PKCS8Generator.PBE_SHA1_RC2_128;
			}
			if (algorithm.equalsIgnoreCase(PBE_SHA1_RC2_40)) {
				return PKCS8Generator.PBE_SHA1_RC2_40;
			}

			throw new CryptoUtilsException(
					"Select Algorithm ID error: algorithm not supported");
		}
		throw new CryptoUtilsException(
				"Select Algorithm ID error: encoding not supported");

	}
}
