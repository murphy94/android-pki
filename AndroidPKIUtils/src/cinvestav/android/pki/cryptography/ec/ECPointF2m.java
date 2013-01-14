/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Elliptic curve points over F2m
 */
package cinvestav.android.pki.cryptography.ec;

import java.security.Security;
import java.security.spec.ECFieldF2m;

import org.spongycastle.asn1.x9.X9ECPoint;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.F2m;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * Elliptic curve points over F2m
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECPointF2m extends F2m {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @param curve
	 *            base curve
	 * @param x
	 *            x point
	 * @param y
	 *            y point
	 */
	public ECPointF2m(ECCurveF2m curve, ECFieldElementF2m x, ECFieldElementF2m y) {
		super(curve, x, y);
	}

	/**
	 * @param curve
	 *            base curve
	 * @param x
	 *            x point
	 * @param y
	 *            y point
	 * @param withCompression
	 *            true if encode with point compression.
	 */
	public ECPointF2m(ECCurveF2m curve, ECFieldElementF2m x,
			ECFieldElementF2m y, boolean withCompression) {
		super(curve, x, y, withCompression);
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
					+ ECFieldElementF2m.parse(getX()).toString(encoder) + ", y="
					+ ECFieldElementF2m.parse(getY()).toString(encoder) + "]";
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			return "[x=" + getX() + ", y=" + getY() + "]";
		}
	}

	/**
	 * Parse a ECPoint ({@link org.spongycastle.math.ec.ECPoint}) to this class
	 * 
	 * @param point
	 *            Instance of ECPoint class
	 * @return A parsed ECPointF2m object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECPoint object
	 */
	public static ECPointF2m parse(ECPoint point)
			throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointF2m parse error: Invalid ECPoint object (null object received)");
		if (point instanceof ECPoint.F2m) {
			return parse((ECPoint.F2m) point);
		}
		throw new CryptoUtilsException(
				"ECPointF2m parse error: Invalid ECPoint object");
	}

	/**
	 * Parse a ECPoint.F2m ({@link org.spongycastle.math.ec.ECPoint.F2m}) to
	 * this class
	 * 
	 * @param point
	 *            Instance of ECPoint.F2m class
	 * @return A parsed ECPointF2m object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECPoint.F2m object
	 */
	public static ECPointF2m parse(ECPoint.F2m point)
			throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointF2m parse error: Invalid ECPoint.F2m object (null object received)");
		return new ECPointF2m(ECCurveF2m.parse((ECCurve.F2m) point.getCurve()),
				ECFieldElementF2m.parse((ECFieldElement.F2m) point.getX()),
				ECFieldElementF2m.parse((ECFieldElement.F2m) point.getY()));
	}

	/**
	 * Parse this object to ECPoint.F2m (SpongyCastle) representation object
	 * 
	 * @return an object of type ECPoint.F2m with the values of the calling
	 *         object
	 */
	public ECPoint.F2m parseToECPoint() {
		return this;
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
	public static ECPointF2m parse(java.security.spec.ECPoint point,
			ECFieldF2m field, ECCurveF2m curve)
			throws CryptoUtilsException {
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointF2m parse error: Invalid ECPoint object (null object received)");

		ECFieldElementF2m x = new ECFieldElementF2m(field.getM(),
				field.getMidTermsOfReductionPolynomial()[0],
				field.getMidTermsOfReductionPolynomial()[1],
				field.getMidTermsOfReductionPolynomial()[2], point.getAffineX());
		ECFieldElementF2m y = new ECFieldElementF2m(field.getM(),
				field.getMidTermsOfReductionPolynomial()[0],
				field.getMidTermsOfReductionPolynomial()[1],
				field.getMidTermsOfReductionPolynomial()[2], point.getAffineY());
		return new ECPointF2m(curve, x, y);
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
	public static ECPointF2m parse(X9ECPoint point) throws CryptoUtilsException{
		if (point == null)
			throw new CryptoUtilsException(
					"ECPointFp parse error: Invalid ECPoint.Fp object (null object received)");
		return parse(point.getPoint());
	}
}
