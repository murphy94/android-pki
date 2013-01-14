/**
 *  Created on  : 09/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.UnsupportedEncodingException;
import java.security.Security;

import org.spongycastle.crypto.Digest;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 09/08/2012
 * @version 1.0
 */
public class DigestCryptoUtils implements IDigestCryptoUtils {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 
	 */
	public DigestCryptoUtils() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IDigestCryptoUtils#getDigest
	 * (byte[], java.lang.String)
	 */
	@Override
	public byte[] getDigest(byte[] input, String algorithm)
			throws CryptoUtilsException {
		Digest digest = CryptoUtils.selectDigest(algorithm);
		byte[] resBuf = new byte[digest.getDigestSize()];

		digest.update(input, 0, input.length);
		digest.doFinal(resBuf, 0);

		return resBuf;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IDigestCryptoUtils#getDigest
	 * (byte[])
	 */
	@Override
	public byte[] getDigest(byte[] input) throws CryptoUtilsException {
		return getDigest(input, CryptoUtils.DIGEST_FUNCTION_SHA_1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IDigestCryptoUtils#getDigest
	 * (java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public String getDigest(String input, String algorithm, String encoder)
			throws CryptoUtilsException {
		try {
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return new String(Base64.encode(getDigest(
						input.getBytes("UTF-8"), algorithm)));
			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return new String(Hex.encode(getDigest(input.getBytes("UTF-8"),
						algorithm)));
			}

			throw new CryptoUtilsException(
					"Digest error: Unsupported encoder [" + encoder + "]");
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IDigestCryptoUtils#getDigest
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public String getDigest(String input, String algorithm)
			throws CryptoUtilsException {
		try {
			return new String(Base64.encode(getDigest(input.getBytes("UTF-8"),
					algorithm)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IDigestCryptoUtils#getDigest
	 * (java.lang.String)
	 */
	@Override
	public String getDigest(String input) throws CryptoUtilsException {
		try {
			return new String(Base64.encode(getDigest(input.getBytes("UTF-8"),
					CryptoUtils.DIGEST_FUNCTION_SHA_1)));
		} catch (UnsupportedEncodingException e) {

			throw new CryptoUtilsException(e.getMessage(), e);
		}
	}

}
