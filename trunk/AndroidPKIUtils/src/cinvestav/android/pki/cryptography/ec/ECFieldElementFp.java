/**
 *  Created on  : 05/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that represents a Field element over FP
 */
package cinvestav.android.pki.cryptography.ec;

import java.math.BigInteger;
import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECFieldElement.Fp;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;

/**
 * Element in the Fp field
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/06/2012
 * @version 1.0
 */
public class ECFieldElementFp extends Fp {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @param p
	 *            Prime that defines the field
	 * @param x
	 *            Value of the field element
	 */
	public ECFieldElementFp(BigInteger p, BigInteger x) {
		super(p, x);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Parse a ECFieldElement ({@link org.spongycastle.math.ec.ECFieldElement})
	 * to this class
	 * 
	 * @param fieldElement
	 *            Intance of ECFieldElement.Fp object
	 * @return A parsed ECFieldElementFP object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECFieldElement.Fp
	 *             object
	 */
	public static ECFieldElementFp parse(ECFieldElement fieldElement)
			throws CryptoUtilsException {
		if (fieldElement == null)
			throw new CryptoUtilsException(
					"ECFieldElementFp parse error: Invalid ECFieldElement.Fp object (null object received)");
		if (fieldElement instanceof ECFieldElement.Fp) {
			return parse((ECFieldElement.Fp) fieldElement);
		}
		throw new CryptoUtilsException(
				"ECFieldElementFp parse error: Invalid ECFieldElement object");
	}

	/**
	 * Parse a ECFieldElement.Fp (
	 * {@link org.spongycastle.math.ec.ECFieldElement.Fp}) to this class
	 * 
	 * @param fieldElement
	 *            Fp field Element object
	 * @return a new ECFieldElementFp object
	 * @throws CryptoUtilsException
	 *             if the parameter does not contain a valid ECFieldElement.Fp
	 *             object
	 */
	public static ECFieldElementFp parse(ECFieldElement.Fp fieldElement) {
		return new ECFieldElementFp(fieldElement.getQ(),
				fieldElement.toBigInteger());
	}

	/**
	 * Parse this object to ECFieldElement.Fp (SpongyCastle) representation
	 * object
	 * 
	 * @return an object of type ECFieldElement.Fp with the values of the
	 *         calling object
	 */
	public ECFieldElement.Fp parseToECFieldElement() {
		return this;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "[" + toBigInteger() + "]";
	}

	/**
	 * ToString method using a specific encoder
	 * 
	 * @param encoder
	 *            see available encoders in
	 *            {@link cinvestav.android.pki.cryptography.utils.CryptoUtils}
	 * @return String EC Field Element FP encoded
	 */
	public String toString(String encoder) {
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			return "["
					+ new String(Base64.encode(toBigInteger().toByteArray()))
					+ "]";
		}
		if (encoder.equalsIgnoreCase(CryptoUtils.ENCODER_HEX)) {
			return "["
					+ new String(Hex.encode(toBigInteger().toByteArray()))
					+ "]";
		}

		return "[" + toBigInteger() + "]";
	}
}
