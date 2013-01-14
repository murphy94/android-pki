/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Elliptic curve points over Fp
 */
package cinvestav.android.pki.cryptography.ec;

import java.security.Security;

import org.spongycastle.asn1.x9.X9ECPoint;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.Fp;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * Elliptic curve points over Fp
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECPointFp extends Fp {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Create a point which encodes with point compression.
	 * 
	 * @param curve
	 *            the curve to use
	 * @param x
	 *            affine x co-ordinate
	 * @param y
	 *            affine y co-ordinate
	 */
	public ECPointFp(ECCurveFp curve, ECFieldElementFp x, ECFieldElementFp y) {
		super(curve, x, y);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Create a point that encodes with or without point compresion.
	 * 
	 * @param curve
	 *            the curve to use
	 * @param x
	 *            affine x co-ordinate
	 * @param y
	 *            affine y co-ordinate
	 * @param withCompression
	 *            if true encode with point compression
	 */
	public ECPointFp(ECCurveFp curve, ECFieldElementFp x, ECFieldElementFp y,
			boolean withCompression) {

		super(curve, x, y, withCompression);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Parse a ECPoint ({@link java.security.spec.ECPoint}) to this class
	 * 
	 * @param point
	 *            Instance of ECPoint class
	 * @return A parsed ECPointFp object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECPoint object
	 */
	public static ECPointFp parse(java.security.spec.ECPoint point,
			ECCurveFp curve) throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointFp parse error: Invalid ECPoint object (null object received)");
		ECFieldElementFp x = new ECFieldElementFp(curve.getQ(),
				point.getAffineX());
		ECFieldElementFp y = new ECFieldElementFp(curve.getQ(),
				point.getAffineY());
		return new ECPointFp(curve, x, y);
	}

	/**
	 * Parse this object to JCE ECPoint representation object
	 * 
	 * @return an JCE ECPoint object with the values of the calling object
	 */
	public java.security.spec.ECPoint parseToJCEECPoint() {
		java.security.spec.ECPoint point = new java.security.spec.ECPoint(this
				.getX().toBigInteger(), this.getY().toBigInteger());
		return point;
	}

	/**
	 * Parse a ECPoint ({@link org.spongycastle.math.ec.ECPoint}) to this class
	 * 
	 * @param point
	 *            Instance of ECPoint class
	 * @return A parsed ECPointFp object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECPoint object
	 */
	public static ECPointFp parse(ECPoint point)
			throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointFp parse error: Invalid ECPoint object (null object received)");
		if (point instanceof ECPoint.Fp) {
			return parse((ECPoint.Fp) point);
		}
		throw new CryptoUtilsException(
				"ECPointFp parse error: Invalid ECPoint object");
	}

	/**
	 * Parse a ECPoint.Fp ({@link org.spongycastle.math.ec.ECPoint.Fp}) to this
	 * class
	 * 
	 * @param point
	 *            Instance of ECPoint.Fp class
	 * @return A parsed ECPointFp object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECPoint.Fp object
	 */
	public static ECPointFp parse(ECPoint.Fp point)
			throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointFp parse error: Invalid ECPoint.Fp object (null object received)");
		return new ECPointFp(ECCurveFp.parse((ECCurve.Fp) point.getCurve()),
				ECFieldElementFp.parse((ECFieldElement.Fp) point.getX()),
				ECFieldElementFp.parse((ECFieldElement.Fp) point.getY()));
	}
	
	/**
	 * Parse this object to X9 ECPoint representation object
	 * 
	 * @return an X9 ECPoint object with the values of the calling object
	 */
	public X9ECPoint parseToX9ECPoint(){
		X9ECPoint pointRes = new X9ECPoint(parseToECPoint());
		return pointRes;
	}
	
	/**
	 * Parse a X9ECPoint ({@link org.spongycastle.asn1.x9.X9ECPoint}) to this
	 * class
	 * 
	 * @param point
	 *            Instance of X9ECPoint class
	 * @return A parsed ECPointFp object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid X9ECPoint object
	 */
	public static ECPointFp parse(X9ECPoint point) throws CryptoUtilsException{
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointFp parse error: Invalid ECPoint.Fp object (null object received)");
		return parse(point.getPoint());
	}

	/**
	 * Parse this object to ECPoint.Fp (SpongyCastle) representation object
	 * 
	 * @return an object of type ECPoint.Fp with the values of the calling
	 *         object
	 */
	public ECPoint.Fp parseToECPoint() {
		return this;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "[x=" + getX() + ", y=" + getY() + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Point FP encoded
	 */
	public String toString(String encoder) {
		try {
			return "[x="
					+ ECFieldElementFp.parse(getX()).toString(encoder) + ", y="
					+ ECFieldElementFp.parse(getY()).toString(encoder) + "]";
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			return "[x=" + getX() + ", y=" + getY() + "]";
		}
	}

}
