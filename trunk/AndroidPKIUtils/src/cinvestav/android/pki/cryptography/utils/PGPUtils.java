/**
 *  Created on  : 01/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPSignatureSubpacketVector;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyConverter;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;

/**
 * Implementation of the Interface IPGPUtils, this class will contain
 * several functions to manage the compatibility with pgp for saving keys,
 * encrypt/decrypt and sing/verify files and byte streams
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 01/06/2012
 * @version 1.0
 */
public class PGPUtils implements IPGPUtils {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private BcPGPKeyConverter pgpKeyConverter;

	public PGPUtils() {
		pgpKeyConverter = new BcPGPKeyConverter();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IPGPUtils#saveRSAPublicKey
	 * (java.lang.String, cinvestav.android.pki.cryptography.key.RSAPublicKey,
	 * java.util.HashMap, cinvestav.android.pki.cryptography.key.RSAKeyPair,
	 * java.lang.Boolean)
	 */
	@Override
	public void saveRSAPublicKey(String fullFileName, RSAPublicKey publicKey,
			HashMap<String, String> publicKeyInformationMap,
			RSAKeyPair issuerKeyPair, Boolean ascArmor)
			throws CryptoUtilsException {

		PGPPublicKey issuerPGPPublicKey;
		try {
			issuerPGPPublicKey = pgpKeyConverter.getPGPPublicKey(
					PGPPublicKey.RSA_GENERAL, issuerKeyPair.getPublicKey()
							.parseToRSAKeyParameters(), new Date());

			PGPPrivateKey issuerPGPSecretKey = pgpKeyConverter
					.getPGPPrivateKey(issuerPGPPublicKey, issuerKeyPair
							.getPrivateKey()
							.parseToRSAPrivateCrtKeyParameters());

			PGPPublicKey pgpPublicKey = pgpKeyConverter.getPGPPublicKey(
					PGPPublicKey.RSA_GENERAL,
					publicKey.parseToRSAKeyParameters(), new Date());

			Iterator<Entry<String, String>> it = publicKeyInformationMap
					.entrySet().iterator();
			while (it.hasNext()) {
				Entry<String, String> pair = it.next();

				String userId = pair.getKey() + " : " + pair.getValue();

				PGPSignatureGenerator sGen = new PGPSignatureGenerator(
						new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL,
								PGPUtil.SHA1));

				sGen.init(PGPSignature.POSITIVE_CERTIFICATION,
						issuerPGPSecretKey);

				PGPSignature certification = sGen.generateCertification(userId,
						pgpPublicKey);

				pgpPublicKey = PGPPublicKey.addCertification(pgpPublicKey,
						userId, certification);

			}

			pgpPublicKey = signPublicKey(issuerPGPSecretKey, pgpPublicKey,
					"SignTest", "SignTestValue", ascArmor);

			File file = new File(fullFileName);
			if (!file.exists()) {
				file.createNewFile();
			}

			OutputStream fos = new FileOutputStream(file);
			if (ascArmor) {
				fos = new ArmoredOutputStream(fos);
			}

			pgpPublicKey.encode(fos);
			fos.close();

		} catch (PGPException e) {
			throw new CryptoUtilsException(
					"Save PGPRSAPublicKey error: " + e, e);
		} catch (SignatureException e) {
			throw new CryptoUtilsException(
					"Save PGPRSAPublicKey error: " + e, e);
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException(
					"Save PGPRSAPublicKey error: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException(
					"Save PGPRSAPublicKey error: " + e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IPGPUtils#loadRSAPublicKey
	 * (java.lang.String)
	 */
	@Override
	public RSAPublicKey loadRSAPublicKey(String fullFileName)
			throws CryptoUtilsException {
		
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IPGPUtils#
	 * loadPublicKeyInformationMap(java.lang.String)
	 */
	@Override
	public HashMap<String, String> loadPublicKeyInformationMap(
			String fullFileName) throws CryptoUtilsException {
		
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IPGPUtils#saveRSAPrivateKey
	 * (java.lang.String, cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.lang.String, java.lang.Boolean)
	 */
	@Override
	public void saveRSAPrivateKey(String fullFileName,
			RSAPrivateKey privateKey, String password, Boolean ascArmor)
			throws CryptoUtilsException {
		

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IPGPUtils#loadRSAPrivateKey
	 * (java.lang.String, java.lang.String)
	 */
	@Override
	public RSAPrivateKey loadRSAPrivateKey(String fullFileName, String password)
			throws CryptoUtilsException {
		
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IPGPUtils#saveRSAKeyPair
	 * (java.lang.String, java.lang.String,
	 * cinvestav.android.pki.cryptography.key.RSAKeyPair, java.util.HashMap,
	 * cinvestav.android.pki.cryptography.key.RSAKeyPair, java.lang.String,
	 * java.lang.Boolean)
	 */
	@Override
	public void saveRSAKeyPair(String fullRSAPublicKeyFileName,
			String fullRSAPrivateKeyFileName, RSAKeyPair keyPair,
			HashMap<String, String> publicKeyInformationMap,
			RSAKeyPair issuerKeyPair, String password, Boolean ascArmor)
			throws CryptoUtilsException {
		

	}

	@SuppressWarnings("resource")
	private PGPPublicKey signPublicKey(PGPPrivateKey pgpPrivKey,
			PGPPublicKey keyToBeSigned, String notationName,
			String notationValue, boolean armor) throws PGPException,
			IOException, SignatureException {
		OutputStream out = new ByteArrayOutputStream();

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		PGPSignatureGenerator sGen = new PGPSignatureGenerator(
				new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL,
						PGPUtil.SHA1));

		sGen.init(PGPSignature.DIRECT_KEY, pgpPrivKey);

		BCPGOutputStream bOut = new BCPGOutputStream(out);

		sGen.generateOnePassVersion(false).encode(bOut);

		PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

		boolean isHumanReadable = true;

		spGen.setNotationData(true, isHumanReadable, notationName,
				notationValue);

		PGPSignatureSubpacketVector packetVector = spGen.generate();
		sGen.setHashedSubpackets(packetVector);

		bOut.flush();

		if (armor) {
			out.close();
		}

		return PGPPublicKey.addCertification(keyToBeSigned, sGen.generate());
	}

}
