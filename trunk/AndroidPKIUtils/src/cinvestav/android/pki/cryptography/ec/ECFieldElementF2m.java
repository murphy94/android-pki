/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class representing the Elements of the finite field
 * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
 * representation. Both trinomial (TPB) and pentanomial (PPB) polynomial
 * basis representations are supported. Gaussian normal basis (GNB)
 * representation is not supported.
 */
package cinvestav.android.pki.cryptography.ec;

import java.math.BigInteger;
import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECFieldElement.F2m;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Class representing the Elements of the finite field
 * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
 * representation. Both trinomial (TPB) and pentanomial (PPB) polynomial basis
 * representations are supported. Gaussian normal basis (GNB) representation is
 * not supported.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECFieldElementF2m extends F2m {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Constructor for TPB.
	 * 
	 * @param m
	 *            The exponent <code>m</code> of
	 *            <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k
	 *            The integer <code>k</code> where <code>x<sup>m</sup> +
	 * x<sup>k</sup> + 1</code> represents the reduction polynomial
	 *            <code>f(z)</code>.
	 * @param x
	 *            The BigInteger representing the value of the field element.
	 */
	public ECFieldElementF2m(int m, int k, BigInteger x) {
		super(m, k, x);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor for PPB.
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
	 * @param x
	 *            The BigInteger representing the value of the field element.
	 */
	public ECFieldElementF2m(int m, int k1, int k2, int k3, BigInteger x) {
		super(m, k1, k2, k3, x);
		// TODO Auto-generated constructor stub
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "[" + toBigInteger() + ", representation()="
				+ getRepresentation() + ", m=" + getM() + ", K1=" + getK1()
				+ ", K2=" + getK2() + ", K3=" + getK3() + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Field Element F2m encoded
	 */
	public String toString(String encoder) {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return "["
					+ new String(Base64.encode(toBigInteger().toByteArray()))
					+ ", representation()=" + getRepresentation() + ", m="
					+ getM() + ", K1=" + getK1() + ", K2=" + getK2() + ", K3="
					+ getK3() + "]";
		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return "["
					+ new String(Hex.encode(toBigInteger().toByteArray()))
					+ ", representation()=" + getRepresentation() + ", m="
					+ getM() + ", K1=" + getK1() + ", K2=" + getK2() + ", K3="
					+ getK3() + "]";
		}

		return "[" + toBigInteger() + ", representation()="
				+ getRepresentation() + ", m=" + getM() + ", K1=" + getK1()
				+ ", K2=" + getK2() + ", K3=" + getK3() + "]";
	}

	/**
	 * Parse a ECFieldElement ({@link org.spongycastle.math.ec.ECFieldElement})
	 * to this class
	 * 
	 * @param fieldElement
	 *            Intance of ECFieldElement.F2m object
	 * @return A parsed ECFieldElementF2m object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECFieldElement.F2m
	 *             object
	 */
	public static ECFieldElementF2m parse(ECFieldElement fieldElement)
			throws CryptoUtilsException {
		if (fieldElement == null)
			throw new CryptoUtilsException(
					"ECFieldElementF2m parse error: Invalid ECFieldElement.F2m object (null object received)");
		if (fieldElement instanceof ECFieldElement.F2m) {
			return parse((ECFieldElement.F2m) fieldElement);
		}
		throw new CryptoUtilsException(
				"ECFieldElementF2m parse error: Invalid ECFieldElement object");
	}

	/**
	 * Parse a ECFieldElement.F2m (
	 * {@link org.spongycastle.math.ec.ECFieldElement.F2m}) to this class
	 * 
	 * @param fieldElement
	 *            F2m field Element object
	 * @return a new ECFieldElementF2m object
	 */
	public static ECFieldElementF2m parse(ECFieldElement.F2m fieldElement) {
		return new ECFieldElementF2m(fieldElement.getM(), fieldElement.getK1(),
				fieldElement.getK2(), fieldElement.getK3(),
				fieldElement.toBigInteger());
	}

	/**
	 * Parse this object to ECFieldElement.F2m (SpongyCastle) representation
	 * object
	 * 
	 * @return an object of type ECFieldElement.F2m with the values of the
	 *         calling object
	 */
	public ECFieldElement.F2m parseToECFieldElement() {
		return this;
	}

}
