/**
 *  Created on  : 03/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.exception;

/**
 * Exception Class created for X509 Certificate Extensions errors
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 03/07/2012
 * @version 1.0
 */
public class CryptoUtilsX509ExtensionException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * 
	 */
	public CryptoUtilsX509ExtensionException() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor that receives the message for the generated exception
	 * @param detailMessage
	 */
	public CryptoUtilsX509ExtensionException(String detailMessage) {
		super(detailMessage);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Constructor that receives the cause of the exception
	 * @param throwable
	 */
	public CryptoUtilsX509ExtensionException(Throwable throwable) {
		super(throwable);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Receives the message and the cause for the exception
	 * @param detailMessage
	 * @param throwable
	 */
	public CryptoUtilsX509ExtensionException(String detailMessage,
			Throwable throwable) {
		super(detailMessage, throwable);
		// TODO Auto-generated constructor stub
	}

}
