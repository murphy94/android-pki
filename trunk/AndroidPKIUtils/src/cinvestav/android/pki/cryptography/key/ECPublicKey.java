/**
 *  Created on  : 07/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Wraps the information of a Elliptic Curve Public Key and contain some parse functions 
 *  	to interact with JCE and SpongyCastle EC public Key representations
 */
package cinvestav.android.pki.cryptography.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEECPublicKey;
import org.spongycastle.jce.spec.ECPublicKeySpec;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Base64;

import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.ec.ECPointF2m;
import cinvestav.android.pki.cryptography.ec.ECPointFp;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Wraps the information of a Elliptic Curve Public Key and contain some parse
 * functions to interact with JCE and SpongyCastle EC public Key representations
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 07/06/2012
 * @version 1.0
 */
public class ECPublicKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Parameters for the public key, curve, order, cofactor, etc
	 */
	private ECDomainParameters params;

	/**
	 * Point in the curve that represents the Public key;
	 */
	private ECPoint q;

	/**
	 * Constructor of a EC public key over Fp
	 * 
	 * @param params
	 *            Curve parameters, this should represent a curve over Fp
	 * @param q
	 *            Point over Fp
	 * @throws CryptoUtilsException
	 *             if the point and the curve are not in the same field (Fp)
	 */
	public ECPublicKey(ECDomainParameters params, ECPointFp q)
			throws CryptoUtilsException {
		super();
		if (!params.getField().equalsIgnoreCase(ECDomainParameters.FIELD_FP)) {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		this.params = params;
		this.q = q;
	}

	/**
	 * Constructor of a EC public key over F2m
	 * 
	 * @param params
	 *            Curve parameters, this should represent a curve over F2m
	 * @param q
	 *            Point over F2m
	 * @throws CryptoUtilsException
	 *             if the point and the curve are not in the same field (F2m)
	 */
	public ECPublicKey(ECDomainParameters params, ECPointF2m q)
			throws CryptoUtilsException {
		super();
		if (!params.getField().equalsIgnoreCase(ECDomainParameters.FIELD_F2M)) {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		this.params = params;
		this.q = q;
	}

	/**
	 * @return the params
	 */
	public ECDomainParameters getParams() {
		return params;
	}

	/**
	 * @param params
	 *            the params to set
	 */
	public void setParams(ECDomainParameters params) {
		this.params = params;
	}

	/**
	 * @return the q point of the public key
	 * @throws CryptoUtilsException
	 *             if the point in the publicKey is not a valid point in Fp
	 */
	public ECPointFp getQFp() throws CryptoUtilsException {
		return ECPointFp.parse(q);
	}

	/**
	 * @return the q point of the public key
	 * @throws CryptoUtilsException
	 *             if the point in the publicKey is not a valid point in F2m
	 */
	public ECPointF2m getQF2m() throws CryptoUtilsException {
		return ECPointF2m.parse(q);
	}

	/**
	 * Gets the point Q of the public Key
	 * 
	 * @return Could return a ECPoint2m if the point is over F2m or ECPointFp if
	 *         the point is over Fp
	 * @throws CryptoUtilsException
	 *             if the point is neither over Fp nor F2m
	 */
	public Object getQ() throws CryptoUtilsException {
		if (q instanceof ECPointF2m) {
			return ECPointF2m.parse(q);
		} else if (q instanceof ECPointFp) {
			return ECPointFp.parse(q);
		}
		throw new CryptoUtilsException("Invalid format of the point");
	}

	/**
	 * Set the point Q to be over Fp
	 * 
	 * @param q
	 *            The point of the public key
	 * @throws CryptoUtilsException
	 *             if the parameters of the public key curve does not correspond
	 *             to a Fp field
	 */
	public void setQ(ECPointFp q) throws CryptoUtilsException {
		if (!params.getField().equalsIgnoreCase(ECDomainParameters.FIELD_FP)) {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		this.q = q;
	}

	/**
	 * Set the point Q to be over F2m
	 * 
	 * @param q
	 *            The point of the public key
	 * @throws CryptoUtilsException
	 *             if the parameters of the public key curve does not correspond
	 *             to a F2m field
	 */
	public void setQ(ECPointF2m q) throws CryptoUtilsException {
		if (!params.getField().equalsIgnoreCase(ECDomainParameters.FIELD_F2M)) {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		this.q = q;
	}

	/**
	 * Parse the SpongyCastle ECPublicKeyParameters (
	 * {@link org.spongycastle.crypto.params.ECPublicKeyParameters}) object
	 * 
	 * @param publicKey
	 *            SpongyCastle ECPublicKeyParameters object
	 * @return a new ECPublicKey object with the values of the received key
	 * @throws CryptoUtilsException
	 *             if the public key point and the curve parameters are
	 *             incongruent (has different fields)
	 */
	public static ECPublicKey parse(ECPublicKeyParameters publicKey)
			throws CryptoUtilsException {
		ECPublicKey publicKeyRes;
		ECDomainParameters param = ECDomainParameters.parse(publicKey
				.getParameters());
		ECPoint qAux = publicKey.getQ();
		if (qAux instanceof ECPoint.F2m
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_F2M)) {
			publicKeyRes = new ECPublicKey(param, ECPointF2m.parse(qAux));
		} else if (qAux instanceof ECPoint.Fp
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_FP)) {
			publicKeyRes = new ECPublicKey(param, ECPointFp.parse(qAux));
		} else {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		return publicKeyRes;

	}

	/**
	 * Parse the calling object to SpongyCastle ECPublicKeyParameters type (
	 * {@link org.spongycastle.crypto.params.ECPublicKeyParameters})
	 * 
	 * @return A SC ECPublicKeyParameters with the values of the calling object
	 */
	public ECPublicKeyParameters parseToECPublicKeyParameters() {
		ECPublicKeyParameters publicKey = new ECPublicKeyParameters(this.q,
				this.params.parseToECDomainParameters());
		return publicKey;
	}

	/**
	 * Parse the SpongyCastle ECPublicKeySpec (
	 * {@link org.spongycastle.jce.spec.ECPublicKeySpec;}) object
	 * 
	 * @param publicKey
	 *            SpongyCastle ECPublicKeySpec object
	 * @return a new ECPublicKey object with the values of the received key
	 * @throws CryptoUtilsException
	 *             if the public key point and the curve parameters are
	 *             incongruent (has different fields)
	 */
	public static ECPublicKey parse(ECPublicKeySpec publicKey)
			throws CryptoUtilsException {
		ECPublicKey publicKeyRes;
		ECDomainParameters param = ECDomainParameters.parse(publicKey
				.getParams());
		ECPoint qAux = publicKey.getQ();
		if (qAux instanceof ECPoint.F2m
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_F2M)) {
			publicKeyRes = new ECPublicKey(param, ECPointF2m.parse(qAux));
		} else if (qAux instanceof ECPoint.Fp
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_FP)) {
			publicKeyRes = new ECPublicKey(param, ECPointFp.parse(qAux));
		} else {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		return publicKeyRes;
	}

	/**
	 * Parse the calling object to SpongyCastle ECPublicKeySpec type (
	 * {@link org.spongycastle.jce.spec.ECPublicKeySpec})
	 * 
	 * @return A SC ECPublicKeySpec with the values of the calling object
	 */
	public ECPublicKeySpec parseToECPublicKeySpec() {
		ECPublicKeySpec publicKey = new ECPublicKeySpec(this.q,
				this.params.parseToECParameterSpec());
		return publicKey;
	}

	/**
	 * Parse the JCE ECPublicKey( {@link java.security.interfaces.ECPublicKey})
	 * object
	 * 
	 * @param publicKey
	 *            JCE EC Public key object
	 * @return A new EC Public Key object of the present class with the values
	 *         of the parameter
	 * @throws CryptoUtilsException
	 *             if the public key point and the curve parameters are
	 *             incongruent (has different fields)
	 */
	public static ECPublicKey parse(
			java.security.interfaces.ECPublicKey publicKey)
			throws CryptoUtilsException {
		// Parse the ECPublicKey to its implementation in bc
		JCEECPublicKey publicKeyAux = new JCEECPublicKey(publicKey);
		// Get the EC Public key parameters
		ECDomainParameters param = ECDomainParameters.parse(publicKeyAux
				.getParameters());
		// Get the public point
		ECPoint qAux = publicKeyAux.engineGetQ();
		ECPublicKey publicKeyRes;
		// Check if the curve is defined over F2m, so the point should be over
		// the same field
		if (qAux instanceof ECPoint.F2m
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_F2M)) {
			publicKeyRes = new ECPublicKey(param, ECPointF2m.parse(qAux));
		} else if (qAux instanceof ECPoint.Fp
				&& param.getField().equalsIgnoreCase(
						ECDomainParameters.FIELD_FP)) {
			publicKeyRes = new ECPublicKey(param, ECPointFp.parse(qAux));
		} else {
			throw new CryptoUtilsException(
					"ECPublicKey constructor error: Incongruent Curve and point fields");
		}
		return publicKeyRes;
	}

	/**
	 * Parse the calling object to JCE ECPublicKey type (
	 * {@link java.security.interfaces.ECPublicKey})
	 * 
	 * @return A JCE ECPublicKey with the values of the calling object
	 */
	public java.security.interfaces.ECPublicKey parseToJCEECPublic() {
		JCEECPublicKey publicKeyAux = new JCEECPublicKey("EC",
				parseToECPublicKeySpec());
		return publicKeyAux;
	}

	/**
	 * Generic parser
	 * 
	 * @param publicKey
	 *            EC Public key object, supported object types are:
	 *            {@link org.spongycastle.crypto.params.ECPublicKeyParameters},
	 *            {@link java.security.interfaces.ECPublicKey},
	 *            {@link org.spongycastle.jce.spec.ECPublicKeySpec}
	 * @throws CryptoUtilsException
	 */
	public static ECPublicKey parse(Object publicKey)
			throws CryptoUtilsException {
		if (publicKey instanceof ECPublicKeyParameters) {
			return parse((ECPublicKeyParameters) publicKey);
		} else if (publicKey instanceof java.security.interfaces.ECPublicKey) {
			return parse((java.security.interfaces.ECPublicKey) publicKey);
		} else if (publicKey instanceof ECPublicKeySpec) {
			return parse((ECPublicKeySpec) publicKey);
		} else {
			throw new CryptoUtilsException(
					"Parse error: Public key object type not supported");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "ECPublicKey [params=" + params + ", q=" + q + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Public Key encoded
	 */
	public String toString(String encoder) {
		try {

			if (params.getField()
					.equalsIgnoreCase(ECDomainParameters.FIELD_F2M)) {
				return "ECPublicKey [params=" + params.toString(encoder)
						+ ", q=" + ECPointF2m.parse(q).toString(encoder) + "]";
			}
			return "ECPublicKey [params=" + params.toString(encoder) + ", q="
					+ ECPointFp.parse(q).toString(encoder) + "]";

		} catch (CryptoUtilsException e) {
			return "ECPublicKey [params=" + params + ", q=" + q + "]";
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ECPublicKey) {
			ECPublicKey key = (ECPublicKey) obj;
			boolean res = key.q.equals(this.q)
					&& key.params.equals(this.params);
			return res;
		} else {
			return false;
		}
	}

	/**
	 * Save the EC Private key in using DER encoding
	 * 
	 * @param publicKeyFullPath
	 *            Path and name of the file in which the key will be saved
	 * @throws CryptoUtilsException
	 */
	public void saveDER(String publicKeyFullPath) throws CryptoUtilsException {
		byte[] serializedPublicBytes;
		try {
			serializedPublicBytes = parseToJCEECPublic().getEncoded();
			// byte[] key = Base64.encode(serializedPublicBytes);

			File file = new File(publicKeyFullPath);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(serializedPublicBytes);
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[savePublicKeyDER]: " + e, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[savePublicKeyDER]: " + e, e);
		}
	}

	/**
	 * Load the Public key from PKCS8 DER encoded file
	 * 
	 * @param publicKeyFullPath
	 *            Path of the public key
	 * @return Public key read from the file
	 * @throws CryptoUtilsException
	 */
	public static ECPublicKey loadDER(String publicKeyFullPath)
			throws CryptoUtilsException {
		try {
			File file = new File(publicKeyFullPath);
			if (file.exists()) {
				FileInputStream fis;

				fis = new FileInputStream(file);

				byte[] key = new byte[(int) file.length()];
				fis.read(key);
				fis.close();

				KeyFactory fact = KeyFactory.getInstance("ECDSA",
						CryptoUtils.PROVIDER);
				return parse((java.security.interfaces.ECPublicKey) fact
						.generatePublic(new X509EncodedKeySpec(key)));

			} else {
				throw new CryptoUtilsException(
						"RSA Public Key file not found :" + publicKeyFullPath);
			}
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			throw new CryptoUtilsException("[loadPublicKeyDER]: " + e, e);
		} catch (IllegalArgumentException e) {
			throw new CryptoUtilsException(
					"Load EC Public Key from DER file error: " + e, e);
		}
	}

	/**
	 * Encodes this ECPublicKey object as a base64 encoded byte array using DER
	 * 
	 * @throws CryptoUtilsException
	 */
	public byte[] encode() throws CryptoUtilsException {
		byte[] serializedPublicBytes;
		serializedPublicBytes = parseToJCEECPublic().getEncoded();

		return Base64.encode(serializedPublicBytes);
	}

	/**
	 * Decodes a byte array encoded using base64 to an ECPublicKey object
	 * 
	 * @param keyBytes
	 *            Base64 encoded byte array representing the key
	 * @return A new ECPublicKey that correspond to the encoded bytes
	 * @throws CryptoUtilsException
	 *             if the byte array does not correspond to a Base64 ECPublicKey
	 *             encoded key
	 */
	public static ECPublicKey decode(byte[] keyBytes)
			throws CryptoUtilsException {

		try {

			KeyFactory fact = KeyFactory.getInstance("ECDSA",
					CryptoUtils.PROVIDER);
			return parse((java.security.interfaces.ECPublicKey) fact
					.generatePublic(new X509EncodedKeySpec(Base64
							.decode(keyBytes))));

		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Decode EC Public Key error: " + e,
					e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Decode EC Public Key error: " + e,
					e);
		} catch (InvalidKeySpecException e) {
			throw new CryptoUtilsException("Decode EC Public Key error: " + e,
					e);
		} catch (Exception e) {
			throw new CryptoUtilsException("Decode EC Public Key error: " + e,
					e);
		}
	}

}
