/**
 *  Created on  : 21/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class will encapsulate all the exceptions generated in the 
 *  	Android Cryptography Utils Library
 *  	
 */
package cinvestav.android.pki.cryptography.exception;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 *
 */
public class CryptoUtilsException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -460797541631159606L;

	/**
	 *	Default Constructor
	 */
	public CryptoUtilsException() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor that receives the message for the generated exception
	 * @param detailMessage
	 */
	public CryptoUtilsException(String detailMessage) {
		super(detailMessage);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor that receives the cause of the exception
	 * @param throwable
	 */
	public CryptoUtilsException(Throwable throwable) {
		super(throwable);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Receives the message and the cause for the exception
	 * @param detailMessage
	 * @param throwable
	 */
	public CryptoUtilsException(String detailMessage, Throwable throwable) {
		super(detailMessage, throwable);
		// TODO Auto-generated constructor stub
	}

}
