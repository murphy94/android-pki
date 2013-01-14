/**
 *  Created on  : 16/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.key;

import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PasswordFinder;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 *
 */
public class DefaultPasswordFinder implements PasswordFinder {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	 private final char [] password;

	/**
	 * 
	 */
	public DefaultPasswordFinder(char [] password) {
		// TODO Auto-generated constructor stub
		this.password = password;
	}

	/* (non-Javadoc)
	 * @see org.spongycastle.openssl.PasswordFinder#getPassword()
	 */
	@Override
	public char[] getPassword() {
		// TODO Auto-generated method stub
		char res[] = new char[password.length];
		System.arraycopy(password, 0, res, 0, password.length);
		return res;
	}

}
