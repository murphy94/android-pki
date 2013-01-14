/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Elliptic curves over F2m. The Weierstrass equation is given by
 * 		<code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
 */
package cinvestav.android.pki.cryptography.ec;

import java.math.BigInteger;
import java.security.Security;
import java.security.spec.ECFieldF2m;
import java.security.spec.EllipticCurve;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Elliptic curves over F2m. The Weierstrass equation is given by
 * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECCurveF2m extends F2m {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Constructor for Trinomial Polynomial Basis (TPB).
	 * 
	 * @param m
	 *            The exponent <code>m</code> of
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k
	 *            The integer <code>k</code> where <code>x<sup>m</sup> +
	 * x<sup>k</sup> + 1</code> represents the reduction polynomial
	 *            <code>f(z)</code>.
	 * @param a
	 *            The coefficient <code>a</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param b
	 *            The coefficient <code>b</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 */
	public ECCurveF2m(int m, int k, BigInteger a, BigInteger b) {
		super(m, k, a, b);

		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor for Trinomial Polynomial Basis (TPB).
	 * 
	 * @param m
	 *            The exponent <code>m</code> of
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k
	 *            The integer <code>k</code> where <code>x<sup>m</sup> +
	 * x<sup>k</sup> + 1</code> represents the reduction polynomial
	 *            <code>f(z)</code>.
	 * @param a
	 *            The coefficient <code>a</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param b
	 *            The coefficient <code>b</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param n
	 *            The order of the main subgroup of the elliptic curve.
	 * @param h
	 *            The cofactor of the elliptic curve, i.e.
	 *            <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>
	 *            .
	 */
	public ECCurveF2m(int m, int k, BigInteger a, BigInteger b, BigInteger n,
			BigInteger h) {
		super(m, k, a, b, n, h);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor for Pentanomial Polynomial Basis (PPB).
	 * 
	 * @param m
	 *            The exponent <code>m</code> of
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k1
	 *            The integer <code>k1</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param k2
	 *            The integer <code>k2</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param k3
	 *            The integer <code>k3</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param a
	 *            The coefficient <code>a</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param b
	 *            The coefficient <code>b</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 */
	public ECCurveF2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b) {
		super(m, k1, k2, k3, a, b);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor for Pentanomial Polynomial Basis (PPB).
	 * 
	 * @param m
	 *            The exponent <code>m</code> of
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k1
	 *            The integer <code>k1</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param k2
	 *            The integer <code>k2</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param k3
	 *            The integer <code>k3</code> where <code>x<sup>m</sup> +
	 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code> represents
	 *            the reduction polynomial <code>f(z)</code>.
	 * @param a
	 *            The coefficient <code>a</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param b
	 *            The coefficient <code>b</code> in the Weierstrass equation for
	 *            non-supersingular elliptic curves over
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param n
	 *            The order of the main subgroup of the elliptic curve.
	 * @param h
	 *            The cofactor of the elliptic curve, i.e.
	 *            <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>
	 *            .
	 */
	public ECCurveF2m(int m, int k1, int k2, int k3, BigInteger a,
			BigInteger b, BigInteger n, BigInteger h) {
		super(m, k1, k2, k3, a, b, n, h);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Parse an ECCurve object to this class
	 * 
	 * @param curve
	 *            Curve to be parsed
	 * @return A new ECCurveF2m object with the values of the specified curve
	 * @throws CryptoUtilsException
	 *             if the parameter is not a valid ECCurve.F2m object
	 */
	public static ECCurveF2m parse(ECCurve curve)
			throws CryptoUtilsException {
		if (curve == null)
			throw new CryptoUtilsException(
					"ECCurveF2m parse error: Invalid ECCurve object (null object received)");
		if (curve instanceof ECCurve.F2m) {
			return parse((ECCurve.F2m) curve);
		}
		throw new CryptoUtilsException(
				"ECCurveF2m parse error: Invalid ECCurve object");
	}

	/**
	 * Parse To ECCurve.F2m (SpongyCastle) curve
	 * 
	 * @return A parsed object
	 */
	public ECCurve.F2m parseToECCurveF2m() {
		return this;
	}

	/**
	 * Parse an ECCurve.F2m object to its wrapper
	 * 
	 * @param curve
	 *            Curve to be parsed
	 * @return A new ECCurveF2m object with the values of the specified curve
	 */
	public static ECCurveF2m parse(ECCurve.F2m curve) {
		return new ECCurveF2m(curve.getM(), curve.getK1(), curve.getK2(),
				curve.getK3(), curve.getA().toBigInteger(), curve.getB()
						.toBigInteger(), curve.getN(), curve.getH());
	}

	/**
	 * Parse an EllipticCurve object to this class
	 * 
	 * @param curve
	 *            EllipticCurve object
	 * @return A new ECCurveFp object with the values of the specified curve
	 * @throws CryptoUtilsException
	 *             if the parameter is not a valid EC over Fp
	 * 
	 */
	public static ECCurveF2m parse(EllipticCurve curve)
			throws CryptoUtilsException {
		if (curve.getField() instanceof ECFieldF2m) {
			ECFieldF2m field = (ECFieldF2m) curve.getField();
			return new ECCurveF2m(field.getM(),
					field.getMidTermsOfReductionPolynomial()[0],
					field.getMidTermsOfReductionPolynomial()[1],
					field.getMidTermsOfReductionPolynomial()[2], curve.getA(),
					curve.getB());
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
		int bases[] = { this.getK1(), this.getK2(), this.getK3() };
		ECFieldF2m field = new ECFieldF2m(this.getM(), bases);
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
		return "ECCurveF2m [a=" + getA() + ", b=" + getB() + ", K1()="
				+ getK1() + ", K2()=" + getK2() + ", K3()=" + getK3()
				+ ", N()=" + getN() + ", H()=" + getH() + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Curve F2m encoded
	 */
	public String toString(String encoder) {
		try {
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				return "ECCurveF2m [a="
						+ ECFieldElementF2m.parse(getA()).toString(encoder)
						+ ", b="
						+ ECFieldElementF2m.parse(getB()).toString(encoder)
						+ ", K1()=" + getK1() + ", K2()=" + getK2() + ", K3()="
						+ getK3() + ", N()="
						+ new String(Base64.encode(getN().toByteArray()))
						+ ", H()="
						+ new String(Base64.encode(getH().toByteArray())) + "]";

			}
			if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
				return "ECCurveF2m [a=" + getA() + ", b=" + getB() + ", K1()="
						+ getK1() + ", K2()=" + getK2() + ", K3()=" + getK3()
						+ ", N()="
						+ new String(Hex.encode(getN().toByteArray()))
						+ ", H()="
						+ new String(Hex.encode(getH().toByteArray())) + "]";
			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			return "ECCurveF2m [a=" + getA() + ", b=" + getB() + ", K1()="
					+ getK1() + ", K2()=" + getK2() + ", K3()=" + getK3()
					+ ", N()=" + getN() + ", H()=" + getH() + "]";
		}

		return "ECCurveF2m [a=" + getA() + ", b=" + getB() + ", K1()="
				+ getK1() + ", K2()=" + getK2() + ", K3()=" + getK3()
				+ ", N()=" + getN() + ", H()=" + getH() + "]";
	}

}
