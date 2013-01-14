/**
 *  Created on  : 19/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	The reasonCode (as specified in RFC5280) is a non-critical CRL entry
 * extension that identifies the reason for the certificate revocation. CRL
 * issuers are strongly encouraged to include meaningful reason codes in CRL
 * entries; however, the reason code CRL entry extension SHOULD be absent
 * instead of using the unspecified (0) reasonCode value.
 */
package cinvestav.android.pki.cryptography.cert;

/**
 * The reasonCode (as specified in RFC5280) is a non-critical CRL entry
 * extension that identifies the reason for the certificate revocation. CRL
 * issuers are strongly encouraged to include meaningful reason codes in CRL
 * entries; however, the reason code CRL entry extension SHOULD be absent
 * instead of using the unspecified (0) reasonCode value.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 19/06/2012
 * @version 1.0
 */
public class X509RevokedCertificateReason {

	/**
	 * There is not an specific reason for the revocation
	 */
	public static final int UNSPECIFIED = 0;
	/**
	 * If the private key has been compromised for any reason
	 */
	public static final int KEY_COMPROMISE = 1;
	/**
	 * The CA that has emitted the certificate has been compromised
	 */
	public static final int CA_COMPROMISE = 2;
	/**
	 * If the owner is no longer affiliated with the CA
	 */
	public static final int AFFILIATION_CHANGED = 3;
	/**
	 * If the certificate of the owner has been replaced
	 */
	public static final int SUPERSEDED = 4;
	/**
	 * If the owner has finish its operations in the company
	 */
	public static final int CESSATION_OF_OPERATION = 5;
	/**
     * 
     */
	public static final int CERTIFICATE_HOLD = 6;
	/**
     * 
     */
	public static final int REMOVE_FROM_CRL = 8;
	/**
	 * The owner has lost its privileges
	 */
	public static final int PRIVILEGE_WITHDRAWN = 9;
	/**
	 * 
	 */
	public static final int AA_COMPROMISE = 10;
}
