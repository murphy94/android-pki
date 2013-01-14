/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Elliptic curve over Fp. The Weierstrass equation is given by
 * <code>y<sup>2</sup> = x<sup>3</sup> + ax + b</code>.
 */
package cinvestav.android.pki.cryptography.ec;

import java.math.BigInteger;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Elliptic curve over Fp. The Weierstrass equation is given by
 * <code>y<sup>2</sup> = x<sup>3</sup> + ax + b</code>.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECCurveFp extends Fp {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @param p
	 *            Prime that defines the field of the curve
	 * @param a
	 *            The coefficient <code>a</code> in the Weierstrass equation
	 * @param b
	 *            The coefficient <code>b</code> in the Weierstrass equation
	 */
	public ECCurveFp(BigInteger p, BigInteger a, BigInteger b) {
		super(p, a, b);

		// TODO Auto-generated constructor stub
	}

	/**
	 * Parse an ECCurve object to this class
	 * 
	 * @param curve
	 *            Curve to be parsed
	 * @return A new ECCurveFp object with the values of the specified curve
	 * @throws CryptoUtilsException
	 *             if the parameter is not a valid ECCurve.Fp object
	 */
	public static ECCurveFp parse(ECCurve curve)
			throws CryptoUtilsException {
		if (curve == null)
			throw new CryptoUtilsException(
					"ECCurveFp parse error: Invalid ECCurve object (null object received)");
		if (curve instanceof ECCurve.Fp) {
			return parse((ECCurve.Fp) curve);
		}
		throw new CryptoUtilsException(
				"ECCurveFp parse error: Invalid ECCurve object");
	}

	/**
	 * Parse an ECCurve.FP object to its wrapper
	 * 
	 * @param curve
	 *            Curve to be parsed
	 * @return A new ECCurveFp object with the values of the specified curve
	 */
	public static ECCurveFp parse(ECCurve.Fp curve) {
		return new ECCurveFp(curve.getQ(), curve.getA().toBigInteger(), curve
				.getB().toBigInteger());
	}

	/**
	 * Parse To ECCurve.Fp (SpongyCastle) curve
	 * 
	 * @return A parsed object
	 */
	public ECCurve.Fp parseToECCurveF2m() {
		return this;
	}

	/**
	 * Parse an EllipticCurve JCE object to this class
	 * 
	 * @param curve
	 *            EllipticCurve object
	 * @return A new ECCurveFp object with the values of the specified curve
	 * @throws CryptoUtilsException
	 *             if the parameter is not a valid EC over Fp
	 * 
	 */
	public static ECCurveFp parse(EllipticCurve curve)
			throws CryptoUtilsException {
		if (curve.getField() instanceof ECFieldFp) {
			ECFieldFp field = (ECFieldFp) curve.getField();
			return new ECCurveFp(field.getP(), curve.getA(), curve.getB());
		}

		throw new CryptoUtilsException(
				"ECCurveFp parse error: Invalid EllipticCurve over Fp object");
	}

	/**
	 * Parse this object to JCE EllipticCurve representation object
	 * 
	 * @return an JCE EllipticCurve object with the values of the calling object
	 */
	public EllipticCurve parseToEllipticCurve() {
		ECFieldFp field = new ECFieldFp(this.getQ());
		EllipticCurve curve = new EllipticCurve(field, this.getA()
				.toBigInteger(), this.getB().toBigInteger());
		return curve;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "ECCurveFp [q=" + getQ() + ", a=" + getA() + ", b=" + getB()
				+ "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Curve Fp encoded
	 */
	public String toString(String encoder) {
		try {
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return "ECCurveFp [q="
						+ new String(Base64.encode(getQ().toByteArray()))
						+ ", a="
						+ ECFieldElementFp.parse(getA()).toString(encoder)
						+ ", b="
						+ ECFieldElementFp.parse(getB()).toString(encoder)
						+ "]";

			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return "ECCurveFp [q="
						+ new String(Hex.encode(getQ().toByteArray())) + ", a="
						+ ECFieldElementFp.parse(getA()).toString(encoder)
						+ ", b="
						+ ECFieldElementFp.parse(getB()).toString(encoder)
						+ "]";
			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			return "ECCurveFp [q=" + getQ() + ", a=" + getA() + ", b=" + getB()
					+ "]";
		}

		return "ECCurveFp [q=" + getQ() + ", a=" + getA() + ", b=" + getB()
				+ "]";
	}
	
	

}
