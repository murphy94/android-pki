/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Domain parameters class for the elliptic Curve, contains the curve, a point G
 * (Generator), a bigInteger n (order of the curve), h (cofactor)
 */
package cinvestav.android.pki.cryptography.ec;

import java.math.BigInteger;
import java.security.Security;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;

import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Domain parameters class for the elliptic Curve, contains the curve, a point G
 * (Generator), a bigInteger n (order of the curve), h (cofactor)
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECDomainParameters extends
		org.spongycastle.crypto.params.ECDomainParameters {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final String NIST_CURVE_B_571 = "B-571";
	public static final String NIST_CURVE_B_409 = "B-409";
	public static final String NIST_CURVE_B_283 = "B-283";
	public static final String NIST_CURVE_B_233 = "B-233";
	public static final String NIST_CURVE_B_163 = "B-163";
	public static final String NIST_CURVE_P_521 = "P-521";
	public static final String NIST_CURVE_P_384 = "P-384";
	public static final String NIST_CURVE_P_256 = "P-256";
	public static final String NIST_CURVE_P_224 = "P-224";
	public static final String NIST_CURVE_P_192 = "P-192";
	public static final String FIELD_FP = "FP";
	public static final String FIELD_F2M = "F2M";

	private String field;

	/**
	 * @param curve
	 *            EC Curve defined over Fp
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 */
	public ECDomainParameters(ECCurveFp curve, ECPointFp G, BigInteger n) {
		super(curve, G, n);
		field = FIELD_FP;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param curve
	 *            EC Curve defined over F2m
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 */
	public ECDomainParameters(ECCurveF2m curve, ECPointF2m G, BigInteger n) {
		super(curve, G, n);
		field = FIELD_F2M;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param curve
	 *            EC Curve defined over Fp
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 * @param h
	 *            Cofactor
	 */
	public ECDomainParameters(ECCurveFp curve, ECPointFp G, BigInteger n,
			BigInteger h) {
		super(curve, G, n, h);
		field = FIELD_FP;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param curve
	 *            EC Curve defined over F2m
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 * @param h
	 *            Cofactor
	 */
	public ECDomainParameters(ECCurveF2m curve, ECPointF2m G, BigInteger n,
			BigInteger h) {
		super(curve, G, n, h);
		field = FIELD_F2M;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param curve
	 *            EC Curve defined over Fp
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 * @param h
	 *            Cofactor
	 * @param seed
	 */
	public ECDomainParameters(ECCurveFp curve, ECPointFp G, BigInteger n,
			BigInteger h, byte[] seed) {
		super(curve, G, n, h, seed);
		field = FIELD_FP;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param curve
	 *            EC Curve defined over Fp
	 * @param G
	 *            Generator or base point
	 * @param n
	 *            Order of the curve
	 * @param h
	 *            Cofactor
	 * @param seed
	 */
	public ECDomainParameters(ECCurveF2m curve, ECPointF2m G, BigInteger n,
			BigInteger h, byte[] seed) {
		super(curve, G, n, h, seed);
		field = FIELD_F2M;
		// TODO Auto-generated constructor stub
	}

	/**
	 * Parse a X9ECParamters object to ECDomain Parameters
	 * 
	 * @param parameters
	 *            X9ECParameters object received
	 * @return
	 * @throws CryptoUtilsException
	 */
	public static ECDomainParameters parse(X9ECParameters parameters)
			throws CryptoUtilsException {
		if (parameters == null)
			throw new CryptoUtilsException(
					"ECDomainParameters parse error: Invalid X9ECParameters object (null object received)");
		if (parameters.getCurve() instanceof ECCurve.Fp
				&& parameters.getG() instanceof ECPoint.Fp) {
			return new ECDomainParameters(
					ECCurveFp.parse(parameters.getCurve()),
					ECPointFp.parse(parameters.getG()), parameters.getN(),
					parameters.getH(), parameters.getSeed());
		} else if (parameters.getCurve() instanceof ECCurve.F2m
				&& parameters.getG() instanceof ECPoint.F2m) {
			return new ECDomainParameters(ECCurveF2m.parse(parameters
					.getCurve()), ECPointF2m.parse(parameters.getG()),
					parameters.getN(), parameters.getH(), parameters.getSeed());
		}

		throw new CryptoUtilsException(
				"ECDomainParameters parse error: Invalid X9ECParameters object (Only Fp and F2m curves and points supported)");
	}

	/**
	 * Parse this object to X9ECParameters representation object
	 * 
	 * @return an X9ECParameters object with the values of the calling object
	 */
	public X9ECParameters parseToX9ECParameters() {
		X9ECParameters params = new X9ECParameters(this.getCurve(),
				this.getG(), this.getN(), this.getH(), this.getSeed());
		return params;
	}

	/**
	 * Parse a ECParameterSpec ({@link ECParameterSpec}) object to ECDomain
	 * Parameters
	 * 
	 * @param parameters
	 *            ECParameterSpec object received
	 * @return
	 * @throws CryptoUtilsException
	 */
	public static ECDomainParameters parse(ECParameterSpec parameters)
			throws CryptoUtilsException {
		if (parameters == null)
			throw new CryptoUtilsException(
					"ECDomainParameters parse error: Invalid X9ECParameters object (null object received)");
		if (parameters.getCurve() instanceof ECCurve.Fp
				&& parameters.getG() instanceof ECPoint.Fp) {
			return new ECDomainParameters(
					ECCurveFp.parse(parameters.getCurve()),
					ECPointFp.parse(parameters.getG()), parameters.getN(),
					parameters.getH(), parameters.getSeed());
		} else if (parameters.getCurve() instanceof ECCurve.F2m
				&& parameters.getG() instanceof ECPoint.F2m) {
			return new ECDomainParameters(ECCurveF2m.parse(parameters
					.getCurve()), ECPointF2m.parse(parameters.getG()),
					parameters.getN(), parameters.getH(), parameters.getSeed());
		}

		throw new CryptoUtilsException(
				"ECDomainParameters parse error: Invalid X9ECParameters object (Only Fp and F2m curves and points supported)");
	}

	/**
	 * Parse this object to ECParameterSpec ({@link ECParameterSpec})
	 * representation object
	 * 
	 * @return an ECParameterSpec object with the values of the calling object
	 */
	public ECParameterSpec parseToECParameterSpec() {
		ECParameterSpec params = new ECParameterSpec(this.getCurve(),
				this.getG(), this.getN(), this.getH(), this.getSeed());
		return params;
	}

	/**
	 * Parse a SpongyCastle ECDomainParameters (
	 * {@link org.spongycastle.crypto.params.ECDomainParameters}) object to
	 * ECDomain Parameters
	 * 
	 * @param parameters
	 *            ECParameterSpec object received
	 * @return
	 * @throws CryptoUtilsException
	 */
	public static ECDomainParameters parse(
			org.spongycastle.crypto.params.ECDomainParameters parameters)
			throws CryptoUtilsException {
		if (parameters == null)
			throw new CryptoUtilsException(
					"ECDomainParameters parse error: Invalid ECDomainParameters object (null object received)");
		if (parameters.getCurve() instanceof ECCurve.Fp
				&& parameters.getG() instanceof ECPoint.Fp) {
			return new ECDomainParameters(
					ECCurveFp.parse(parameters.getCurve()),
					ECPointFp.parse(parameters.getG()), parameters.getN(),
					parameters.getH(), parameters.getSeed());
		} else if (parameters.getCurve() instanceof ECCurve.F2m
				&& parameters.getG() instanceof ECPoint.F2m) {
			return new ECDomainParameters(ECCurveF2m.parse(parameters
					.getCurve()), ECPointF2m.parse(parameters.getG()),
					parameters.getN(), parameters.getH(), parameters.getSeed());
		}

		throw new CryptoUtilsException(
				"ECDomainParameters parse error: Invalid ECDomainParameters object (Only Fp and F2m curves and points supported)");
	}

	/**
	 * Parse this object to SpongyCastle ECDomainParameters (
	 * {@link org.spongycastle.crypto.params.ECDomainParameters}) representation
	 * object
	 * 
	 * @return an ECParameterSpec object with the values of the calling object
	 */
	public org.spongycastle.crypto.params.ECDomainParameters parseToECDomainParameters() {
		org.spongycastle.crypto.params.ECDomainParameters params = new org.spongycastle.crypto.params.ECDomainParameters(
				this.getCurve(), this.getG(), this.getN(), this.getH(),
				this.getSeed());
		return params;
	}

	/**
	 * Parse a JCE ECParameterSpec ({@link ECParameterSpec}) object to ECDomain
	 * Parameters
	 * 
	 * @param parameters
	 *            ECParameterSpec object received
	 * @return
	 * @throws CryptoUtilsException
	 */

	public static ECDomainParameters parse(
			java.security.spec.ECParameterSpec parameters)
			throws CryptoUtilsException {
		if (parameters == null)
			throw new CryptoUtilsException(
					"ECDomainParameters parse error: Invalid X9ECParameters object (null object received)");
		if (parameters.getCurve().getField() instanceof ECFieldFp) {
			ECCurveFp curve = ECCurveFp.parse(parameters.getCurve());
			return new ECDomainParameters(curve, ECPointFp.parse(
					parameters.getGenerator(), curve), parameters.getOrder(),
					BigInteger.valueOf(parameters.getCofactor()));
		} else if (parameters.getCurve().getField() instanceof ECFieldF2m) {
			ECFieldF2m field = (ECFieldF2m) parameters.getCurve().getField();
			ECCurveF2m curve = ECCurveF2m.parse(parameters.getCurve());
			return new ECDomainParameters(curve, ECPointF2m.parse(
					parameters.getGenerator(), field, curve),
					parameters.getOrder(), BigInteger.valueOf(parameters
							.getCofactor()));
		}

		throw new CryptoUtilsException(
				"ECDomainParameters parse error: Invalid X9ECParameters object (Only Fp and F2m curves and points supported)");
	}

	public java.security.spec.ECParameterSpec parseToJCEECParameterSpec()
			throws CryptoUtilsException {
		java.security.spec.ECParameterSpec params;
		// Check if the curve of the domain parameters is over Fp or F2m
		if (this.getCurve() instanceof ECCurve.Fp) {
			params = new java.security.spec.ECParameterSpec(ECCurveFp.parse(
					this.getCurve()).parseToEllipticCurve(), ECPointFp.parse(
					this.getG()).parseToJCEECPoint(), this.getN(), this.getH()
					.intValue());
			return params;
		}
		params = new java.security.spec.ECParameterSpec(ECCurveF2m.parse(
				this.getCurve()).parseToEllipticCurve(), ECPointF2m.parse(
				this.getG()).parseToJCEECPoint(), this.getN(), this.getH()
				.intValue());
		return params;

	}

	/**
	 * Get the Domain Parameters for Nist Elliptic Curves using the name of the
	 * curve, check static NIST_CURVE_X_### values in this class for supported
	 * curves;
	 * 
	 * @param name
	 *            Name of the curve, as published in FIPS-PUB 186-2
	 * @return EC Domain Parameters of the curve
	 * @throws CryptoUtilsException
	 *             if the desired curve its not defined
	 */
	public static ECDomainParameters getByNistECName(String name)
			throws CryptoUtilsException {

		X9ECParameters p = NISTNamedCurves.getByName(name);
		if (p == null)
			throw new CryptoUtilsException(
					"Get ECDomainParameters by Nist EC Name error: No such Nist curve");
		return parse(p);
	}

	/**
	 * @return the field of the curve defined
	 */
	public String getField() {
		return field;
	}

	@Override
	public String toString() {
		return "ECDomainParameters [curve=" + getCurve() + ", G=" + getG()
				+ ", n=" + getN() + ", h=" + getH() + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Domain Parameters encoded
	 */
	public String toString(String encoder) {
		try {
			// Check encoder type
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				// For base64, check if the curve is over Fp or F2m
				if (this.getCurve() instanceof ECCurve.Fp) {
					return "ECDomainParameters [curve="
							+ ECCurveFp.parse(getCurve()).toString(encoder)
							+ ", G="
							+ ECPointFp.parse(getG()).toString(encoder)
							+ ", n="
							+ new String(Base64.encode(getN().toByteArray()))
							+ ", h="
							+ new String(Base64.encode(getH().toByteArray()))
							+ "]";
				}
				return "ECDomainParameters [curve="
						+ ECCurveF2m.parse(getCurve()).toString(encoder)
						+ ", G=" + ECPointF2m.parse(getG()).toString(encoder)
						+ ", n="
						+ new String(Base64.encode(getN().toByteArray()))
						+ ", h="
						+ new String(Base64.encode(getH().toByteArray())) + "]";

			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				// For Hex, check if the curve is over Fp or F2m
				if (this.getCurve() instanceof ECCurve.Fp) {
					return "ECDomainParameters [curve="
							+ ECCurveFp.parse(getCurve()).toString(encoder)
							+ ", G="
							+ ECPointFp.parse(getG()).toString(encoder)
							+ ", n="
							+ new String(Hex.encode(getN().toByteArray()))
							+ ", h="
							+ new String(Hex.encode(getH().toByteArray()))
							+ "]";
				}
				return "ECDomainParameters [curve="
						+ ECCurveF2m.parse(getCurve()).toString(encoder)
						+ ", G=" + ECPointF2m.parse(getG()).toString(encoder)
						+ ", n=" + new String(Hex.encode(getN().toByteArray()))
						+ ", h=" + new String(Hex.encode(getH().toByteArray()))
						+ "]";
			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			return "ECDomainParameters [curve=" + getCurve() + ", G=" + getG()
					+ ", n=" + getN() + ", h=" + getH() + "]";
		}

		return "ECDomainParameters [curve=" + getCurve() + ", G=" + getG()
				+ ", n=" + getN() + ", h=" + getH() + "]";
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ECDomainParameters) {
			ECDomainParameters params = (ECDomainParameters) obj;
			boolean res = params.field.equalsIgnoreCase(this.field) &&
					params.getH().equals(this.getH()) && params.getN().equals(this.getN()) &&
					params.getCurve().equals(this.getCurve()); 
			return res;
		} else {
			return false;
		}
	}

}
