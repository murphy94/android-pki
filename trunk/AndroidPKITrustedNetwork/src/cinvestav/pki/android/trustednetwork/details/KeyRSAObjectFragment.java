/**
 *  Created on  : 01/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, displays the advanced key
 * information for rsa.
 */
package cinvestav.pki.android.trustednetwork.details;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;
import com.actionbarsherlock.app.SherlockFragmentActivity;

/**
 * A fragment representing a section of the app, displays the advanced key
 * information for rsa.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 01/09/2012
 * @version 1.0
 */
public class KeyRSAObjectFragment extends SherlockFragment {

	private static final String KEY_ID = "KEY_ID";
	private static final String PASSWORD = "PASSWORD";
	private static final String PASSWORD_PKCS = "PASSWORD_PKCS";

	PersonalKeyDAO key;
	PersonalKeyController personalKeyController;
	Integer keyId;
	LoadRSAPrivateKeyDetailsTask loadRSAPrivateKeyTask;
	LoadRSAPublicKeyDetailsTask loadRSAPublicKeyTask;
	LoadRSAPKCS12KeyDetailsTask loadRSAPKCS12KeyTask;

	String keyPassword;
	String pkcs12Password;

	TextView keySize;
	TextView keyModulus;
	TextView keyPrivateExponent;
	TextView keyPublicExponent;
	TextView keyPrimeA;
	TextView keyPrimeB;
	TextView keyExponentA;
	TextView keyExponentB;
	TextView keyCoefficient;

	public KeyRSAObjectFragment() {
		super();
		keyId = 0;
		keyPassword = "";
		pkcs12Password = "";
	}

	public static KeyRSAObjectFragment newInstance(PersonalKeyDAO key) {
		KeyRSAObjectFragment f = new KeyRSAObjectFragment();
		f.setKey(key);
		f.setPkcs12Password("");
		f.setKeyPassword("");
		return f;
	}

	public static KeyRSAObjectFragment newInstance(PersonalKeyDAO key,
			String keyPassword) {
		KeyRSAObjectFragment f = new KeyRSAObjectFragment();
		f.setKey(key);
		f.setPkcs12Password("");
		f.setKeyPassword(keyPassword);
		return f;
	}

	public static KeyRSAObjectFragment newInstance(PersonalKeyDAO key,
			String keyPassword, String pkcs12Password) {
		KeyRSAObjectFragment f = new KeyRSAObjectFragment();
		f.setKey(key);
		f.setPkcs12Password(pkcs12Password);
		f.setKeyPassword(keyPassword);
		return f;
	}

	/**
	 * @return the key
	 */
	public PersonalKeyDAO getKey() {
		return key;
	}

	/**
	 * @param key
	 *            the key to set
	 */
	public void setKey(PersonalKeyDAO key) {
		this.key = key;
	}

	/**
	 * @return the privateKeyId
	 */
	public Integer getKeyId() {
		return keyId;
	}

	/**
	 * @param privateKeyId
	 *            the privateKeyId to set
	 */
	public void setKeyId(Integer keyId) {
		this.keyId = keyId;
	}

	/**
	 * @return the keyPassword
	 */
	public String getKeyPassword() {
		return keyPassword;
	}

	/**
	 * @param keyPassword
	 *            the keyPassword to set
	 */
	public void setKeyPassword(String keyPassword) {
		this.keyPassword = keyPassword;
	}

	/**
	 * @return the pkcs12Password
	 */
	public String getPkcs12Password() {
		return pkcs12Password;
	}

	/**
	 * @param pkcs12Password
	 *            the pkcs12Password to set
	 */
	public void setPkcs12Password(String pkcs12Password) {
		this.pkcs12Password = pkcs12Password;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.detail_key_fragment_rsa,
				container, false);
		setRetainInstance(true);
		
		Log.i(PKITrustNetworkActivity.TAG, "RSA KEY DETAILS: " + keyId);
		if (savedInstanceState != null && key == null) {
			keyId = savedInstanceState.getInt(KEY_ID);
			keyPassword = savedInstanceState.getString(PASSWORD);
			pkcs12Password = savedInstanceState.getString(PASSWORD_PKCS);
			if (personalKeyController == null) {
				personalKeyController = new PersonalKeyController(getActivity());

			}
			try {
				key = personalKeyController.getById(keyId);
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e.getCause());
			}
		}

		// Get the textView objects from the view
		keySize = ((TextView) rootView.findViewById(R.id.txtDetailsKeyRSASize));
		keyModulus = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAModulus));
		keyPublicExponent = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAPublicExp));
		keyPrivateExponent = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAPrivateExp));

		keyPrimeA = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAPrimeA));
		keyPrimeB = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAPrimeB));
		keyExponentA = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAExponentA));
		keyExponentB = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSAExponentB));
		keyCoefficient = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyRSACoefficient));

		// If the key is RSA Private or RSA Public, initis the corresponding
		// loading task
		if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_RSA)) {
			loadRSAPrivateKeyTask = new LoadRSAPrivateKeyDetailsTask();
			loadRSAPrivateKeyTask.execute(key);
		} else if (key.getKeyType().equals(PersonalKeyDAO.PUBLIC_RSA)) {
			rootView.findViewById(R.id.lblDetailsKeyRSAPrivateExp)
					.setVisibility(View.GONE);
			rootView.findViewById(R.id.lblDetailsKeyRSAPrimeA).setVisibility(
					View.GONE);
			rootView.findViewById(R.id.lblDetailsKeyRSAPrimeB).setVisibility(
					View.GONE);
			rootView.findViewById(R.id.lblDetailsKeyRSAExponentA)
					.setVisibility(View.GONE);
			rootView.findViewById(R.id.lblDetailsKeyRSAExponentB)
					.setVisibility(View.GONE);
			rootView.findViewById(R.id.lblDetailsKeyRSACoefficient)
					.setVisibility(View.GONE);

			loadRSAPublicKeyTask = new LoadRSAPublicKeyDetailsTask();
			loadRSAPublicKeyTask.execute(key);
		} else {
			// RSA as PKCS12
			loadRSAPKCS12KeyTask = new LoadRSAPKCS12KeyDetailsTask();
			loadRSAPKCS12KeyTask.execute(key);
		}

		// Assign on click listener to the button
		((TextView) rootView.findViewById(R.id.lblImgHideDetails))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						if (loadRSAPrivateKeyTask != null)
							loadRSAPrivateKeyTask.cancel(true);
						if (loadRSAPublicKeyTask != null)
							loadRSAPublicKeyTask.cancel(true);
						if (loadRSAPKCS12KeyTask != null)
							loadRSAPKCS12KeyTask.cancel(true);
						// Disable the indeterminate progress icon on the
						// action bar
						((SherlockFragmentActivity) getActivity())
								.setSupportProgressBarIndeterminateVisibility(false);

						((OnClickRSADetailsListener) getActivity())
								.onHideRSADetails(key);

					}
				});

		return rootView;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.Fragment#onDestroy()
	 */
	@Override
	public void onDestroy() {
		if (loadRSAPrivateKeyTask != null)
			loadRSAPrivateKeyTask.cancel(true);
		if (loadRSAPublicKeyTask != null)
			loadRSAPublicKeyTask.cancel(true);
		if (loadRSAPKCS12KeyTask != null)
			loadRSAPKCS12KeyTask.cancel(true);
		// Disable the indeterminate progress icon on the
		// action bar
		((SherlockFragmentActivity) getActivity())
				.setSupportProgressBarIndeterminateVisibility(false);
		super.onDestroy();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.Fragment#onSaveInstanceState(android.os.Bundle)
	 */
	@Override
	public void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);
		outState.putInt(KEY_ID, key.getId());
		outState.putString(PASSWORD, keyPassword);
		outState.putString(PASSWORD_PKCS, pkcs12Password);
	}

	/**
	 * Interface that handles the click on HideDetails button for
	 * {@link KeyRSAObjectFragment}, this should be implemented by the Activity
	 * that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickRSADetailsListener {
		/**
		 * Function for hide the details and load the key basic information
		 * 
		 * @param key
		 *            key to be loaded
		 */
		void onHideRSADetails(PersonalKeyDAO key);
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateKey} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadRSAPrivateKeyDetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, RSAPrivateKey> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected RSAPrivateKey doInBackground(PersonalKeyDAO... params) {

			try {
				return RSAPrivateKey.decode(params[0].getKeyStr().getBytes(),
						keyPassword);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(RSAPrivateKey privateKey) {
			if (privateKey != null) {
				keySize.setText(Integer.toString(privateKey.getModulus()
						.bitLength()));
				keyModulus.setText(privateKey.getModulus().toString(16)
						.toUpperCase());
				keyPublicExponent.setText(privateKey.getPublicExponent()
						.toString(16).toUpperCase());
				keyPrivateExponent.setText(privateKey.getPrivateExponent()
						.toString(16).toUpperCase());
				keyPrimeA.setText(privateKey.getPrime1().toString(16)
						.toUpperCase());
				keyPrimeB.setText(privateKey.getPrime2().toString(16)
						.toUpperCase());
				keyExponentA.setText(privateKey.getExponent1().toString(16)
						.toUpperCase());
				keyExponentB.setText(privateKey.getExponent2().toString(16)
						.toUpperCase());
				keyCoefficient.setText(privateKey.getCoefficient().toString(16)
						.toUpperCase());

			} else {
				Toast.makeText(getActivity(), R.string.error_key_decode,
						Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(false);

		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateKey} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadRSAPublicKeyDetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, RSAPublicKey> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected RSAPublicKey doInBackground(PersonalKeyDAO... params) {

			try {
				return RSAPublicKey.decode(params[0].getKeyStr().getBytes());
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(RSAPublicKey publicKey) {
			if (publicKey != null) {
				keySize.setText(Integer.toString(publicKey.getModulus()
						.bitLength()));
				keyModulus.setText(publicKey.getModulus().toString(16)
						.toUpperCase());
				keyPublicExponent.setText(publicKey.getPublicExponent()
						.toString(16).toUpperCase());

			} else {
				Toast.makeText(getActivity(), R.string.error_key_decode,
						Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(false);

		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAKeyPair} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadRSAPKCS12KeyDetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, RSAKeyPair> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected RSAKeyPair doInBackground(PersonalKeyDAO... params) {

			try {
				Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(params[0]
						.getKeyStr().getBytes(), pkcs12Password, keyPassword);
				return (RSAKeyPair) decodedRSAKeyPair[0];

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(RSAKeyPair keyPair) {
			if (keyPair != null) {
				keySize.setText(Integer.toString(keyPair.getPrivateKey()
						.getModulus().bitLength()));
				keyModulus.setText(keyPair.getPrivateKey().getModulus()
						.toString(16).toUpperCase());
				keyPublicExponent.setText(keyPair.getPrivateKey()
						.getPublicExponent().toString(16).toUpperCase());
				keyPrivateExponent.setText(keyPair.getPrivateKey()
						.getPrivateExponent().toString(16).toUpperCase());
				keyPrimeA.setText(keyPair.getPrivateKey().getPrime1()
						.toString(16).toUpperCase());
				keyPrimeB.setText(keyPair.getPrivateKey().getPrime2()
						.toString(16).toUpperCase());
				keyExponentA.setText(keyPair.getPrivateKey().getExponent1()
						.toString(16).toUpperCase());
				keyExponentB.setText(keyPair.getPrivateKey().getExponent2()
						.toString(16).toUpperCase());
				keyCoefficient.setText(keyPair.getPrivateKey().getCoefficient()
						.toString(16).toUpperCase());

			} else {
				Toast.makeText(getActivity(), R.string.error_key_decode,
						Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(false);

		}
	}
}
