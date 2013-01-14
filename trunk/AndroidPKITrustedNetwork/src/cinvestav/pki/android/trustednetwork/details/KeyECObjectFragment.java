/**
 *  Created on  : 01/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, displays the advanced key
 * information for ec keys.
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
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.ec.ECPointF2m;
import cinvestav.android.pki.cryptography.ec.ECPointFp;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;
import com.actionbarsherlock.app.SherlockFragmentActivity;

/**
 * A fragment representing a section of the app, displays the advanced key
 * information for ec keys.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 01/09/2012
 * @version 1.0
 */
public class KeyECObjectFragment extends SherlockFragment {

	private static final String KEY_ID = "KEY_ID";
	private static final String PASSWORD = "PASSWORD";
	private static final String PASSWORD_PKCS = "PASSWORD_PKCS";

	PersonalKeyDAO key;
	PersonalKeyController personalKeyController;
	Integer keyId;
	LoadECPrivateKeyDetailsTask loadECPrivateKeyTask;
	LoadECPublicKeyDetailsTask loadECPublicKeyTask;
	LoadECPKCS12DetailsTask loadECPKCS12KeyTask;
	String keyPassword;
	String pkcs12Password;

	TextView fieldSize;
	TextView field;
	TextView privatePart;
	TextView publicPart;
	TextView curveGenerator;
	TextView curveA;
	TextView curveB;
	TextView curveOrder;
	TextView curveCofactor;

	public KeyECObjectFragment() {
		super();
		keyId = 0;
		keyPassword = "";
		pkcs12Password = "";
	}

	public static KeyECObjectFragment newInstance(PersonalKeyDAO key) {
		KeyECObjectFragment f = new KeyECObjectFragment();
		f.setKey(key);
		f.setPkcs12Password("");
		f.setKeyPassword("");
		return f;
	}

	public static KeyECObjectFragment newInstance(PersonalKeyDAO key,
			String keyPassword) {
		KeyECObjectFragment f = new KeyECObjectFragment();
		f.setKey(key);
		f.setPkcs12Password("");
		f.setKeyPassword(keyPassword);
		return f;
	}

	public static KeyECObjectFragment newInstance(PersonalKeyDAO key,
			String keyPassword, String pkcs12Password) {
		KeyECObjectFragment f = new KeyECObjectFragment();
		f.setKey(key);
		f.setPkcs12Password(pkcs12Password);
		f.setKeyPassword(keyPassword);
		return f;
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

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.detail_key_fragment_ec,
				container, false);
		setRetainInstance(true);
		Log.i(PKITrustNetworkActivity.TAG, "EC KEY DETAILS");
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
		fieldSize = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECFieldSize));
		field = ((TextView) rootView.findViewById(R.id.txtDetailsKeyECField));
		publicPart = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECPublic));
		privatePart = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECPrivate));

		curveGenerator = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECGenerator));
		curveA = ((TextView) rootView.findViewById(R.id.txtDetailsKeyECCurveA));
		curveB = ((TextView) rootView.findViewById(R.id.txtDetailsKeyECCurveB));
		curveOrder = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECOrder));
		curveCofactor = ((TextView) rootView
				.findViewById(R.id.txtDetailsKeyECCofactor));

		// If the key is EC Private or EC Public, initis the corresponding
		// loading task
		if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
			rootView.findViewById(R.id.lblDetailsKeyECPublic).setVisibility(
					View.GONE);
			loadECPrivateKeyTask = new LoadECPrivateKeyDetailsTask();
			loadECPrivateKeyTask.execute(key);
		} else if (key.getKeyType().equals(PersonalKeyDAO.PUBLIC_EC)) {
			rootView.findViewById(R.id.lblDetailsKeyECPrivate).setVisibility(
					View.GONE);
			loadECPublicKeyTask = new LoadECPublicKeyDetailsTask();
			loadECPublicKeyTask.execute(key);
		} else {
			// Is PKCS12EC
			loadECPKCS12KeyTask = new LoadECPKCS12DetailsTask();
			loadECPKCS12KeyTask.execute(key);
		}

		// Assign on click listener to the button
		((TextView) rootView.findViewById(R.id.lblImgHideDetails))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						if (loadECPrivateKeyTask != null)
							loadECPrivateKeyTask.cancel(true);
						if (loadECPublicKeyTask != null)
							loadECPublicKeyTask.cancel(true);
						if (loadECPKCS12KeyTask != null)
							loadECPKCS12KeyTask.cancel(true);
						// Disable the indeterminate progress icon on the
						// action bar
						((SherlockFragmentActivity) getActivity())
								.setSupportProgressBarIndeterminateVisibility(false);

						((OnClickECDetailsListener) getActivity())
								.onHideECDetails(key);

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
		if (loadECPrivateKeyTask != null)
			loadECPrivateKeyTask.cancel(true);
		if (loadECPublicKeyTask != null)
			loadECPublicKeyTask.cancel(true);
		if (loadECPKCS12KeyTask != null)
			loadECPKCS12KeyTask.cancel(true);
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
	 * Interface that handles the click on Details button for
	 * {@link KeyECObjectFragment}, this should be implemented by the Activity
	 * that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickECDetailsListener {
		/**
		 * Function for hide the details and load the key basic information
		 * 
		 * @param key
		 *            key to be loaded
		 */
		void onHideECDetails(PersonalKeyDAO key);
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPrivateKey} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadECPrivateKeyDetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, ECPrivateKey> {

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
		protected ECPrivateKey doInBackground(PersonalKeyDAO... params) {

			try {
				return ECPrivateKey.decode(params[0].getKeyStr().getBytes(),
						keyPassword);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(ECPrivateKey privateKey) {
			if (privateKey != null) {
				fieldSize.setText(Integer.toString(privateKey.getParams()
						.getCurve().getFieldSize()));
				field.setText(privateKey.getParams().getField().toUpperCase());
				privatePart.setText(privateKey.getD().toString(16)
						.toUpperCase());
				if (privateKey.getParams().getField()
						.equals(ECDomainParameters.FIELD_FP)) {
					curveGenerator.setText(((ECPointFp) privateKey.getParams()
							.getG()).toString(CryptoUtils.ENCODER_HEX)
							.toUpperCase());
					curveA.setText(privateKey.getParams().getCurve().getA()
							.toBigInteger().toString(16).toUpperCase());
					curveB.setText(privateKey.getParams().getCurve().getB()
							.toBigInteger().toString(16).toUpperCase());
				} else {
					curveGenerator.setText(((ECPointF2m) privateKey.getParams()
							.getG()).toString(CryptoUtils.ENCODER_HEX)
							.toUpperCase());
					curveA.setText(privateKey.getParams().getCurve().getA()
							.toBigInteger().toString(16).toUpperCase());
					curveB.setText(privateKey.getParams().getCurve().getB()
							.toBigInteger().toString(16).toUpperCase());
				}
				curveOrder.setText(privateKey.getParams().getN().toString(16)
						.toUpperCase());
				curveCofactor.setText(privateKey.getParams().getH()
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
	 * {@link ECPrivateKey} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadECPublicKeyDetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, ECPublicKey> {

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
		protected ECPublicKey doInBackground(PersonalKeyDAO... params) {

			try {
				return ECPublicKey.decode(params[0].getKeyStr().getBytes());
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(ECPublicKey publicKey) {
			if (publicKey != null) {
				fieldSize.setText(Integer.toString(publicKey.getParams()
						.getCurve().getFieldSize()));
				field.setText(publicKey.getParams().getField().toUpperCase());
				if (publicKey.getParams().getField()
						.equals(ECDomainParameters.FIELD_FP)) {
					try {
						publicPart.setText(publicKey.getQFp()
								.toString(CryptoUtils.ENCODER_HEX)
								.toUpperCase());
					} catch (CryptoUtilsException e) {
					}
					curveGenerator.setText(((ECPointFp) publicKey.getParams()
							.getG()).toString(CryptoUtils.ENCODER_HEX)
							.toUpperCase());
					curveA.setText(publicKey.getParams().getCurve().getA()
							.toBigInteger().toString(16).toUpperCase());
					curveB.setText(publicKey.getParams().getCurve().getB()
							.toBigInteger().toString(16).toUpperCase());
				} else {
					try {
						publicPart.setText(publicKey.getQF2m()
								.toString(CryptoUtils.ENCODER_HEX)
								.toUpperCase());
					} catch (CryptoUtilsException e) {
					}
					curveGenerator.setText(((ECPointF2m) publicKey.getParams()
							.getG()).toString(CryptoUtils.ENCODER_HEX)
							.toUpperCase());
					curveA.setText(publicKey.getParams().getCurve().getA()
							.toBigInteger().toString(16).toUpperCase());
					curveB.setText(publicKey.getParams().getCurve().getB()
							.toBigInteger().toString(16).toUpperCase());
				}
				curveOrder.setText(publicKey.getParams().getN().toString(16)
						.toUpperCase());
				curveCofactor.setText(publicKey.getParams().getH().toString(16)
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
	 * Inner class that create an asynchronous task in which a {@link ECKeyPair}
	 * is loaded and decoded from a {@link PersonalKeyDAO} object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class LoadECPKCS12DetailsTask extends
			AsyncTask<PersonalKeyDAO, Void, ECKeyPair> {

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
		protected ECKeyPair doInBackground(PersonalKeyDAO... params) {

			try {
				Object[] decodedECKeyPair = ECKeyPair.decodePKCS12(params[0]
						.getKeyStr().getBytes(), pkcs12Password, keyPassword);
				return (ECKeyPair) decodedECKeyPair[0];
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(ECKeyPair keyPair) {
			if (keyPair != null) {
				fieldSize.setText(Integer.toString(keyPair.getPrivateKey()
						.getParams().getCurve().getFieldSize()));
				field.setText(keyPair.getPrivateKey().getParams().getField()
						.toUpperCase());
				privatePart.setText(keyPair.getPrivateKey().getD().toString(16)
						.toUpperCase());
				if (keyPair.getPrivateKey().getParams().getField()
						.equals(ECDomainParameters.FIELD_FP)) {
					try {
						publicPart.setText(keyPair.getPublicKey().getQFp()
								.toString(CryptoUtils.ENCODER_HEX)
								.toUpperCase());
					} catch (CryptoUtilsException e) {
					}
					curveGenerator.setText(((ECPointFp) keyPair.getPrivateKey()
							.getParams().getG()).toString(
							CryptoUtils.ENCODER_HEX).toUpperCase());
					curveA.setText(keyPair.getPrivateKey().getParams()
							.getCurve().getA().toBigInteger().toString(16)
							.toUpperCase());
					curveB.setText(keyPair.getPrivateKey().getParams()
							.getCurve().getB().toBigInteger().toString(16)
							.toUpperCase());
				} else {
					try {
						publicPart.setText(keyPair.getPublicKey().getQF2m()
								.toString(CryptoUtils.ENCODER_HEX)
								.toUpperCase());
					} catch (CryptoUtilsException e) {
					}
					curveGenerator.setText(((ECPointF2m) keyPair
							.getPrivateKey().getParams().getG()).toString(
							CryptoUtils.ENCODER_HEX).toUpperCase());
					curveA.setText(keyPair.getPrivateKey().getParams()
							.getCurve().getA().toBigInteger().toString(16)
							.toUpperCase());
					curveB.setText(keyPair.getPrivateKey().getParams()
							.getCurve().getB().toBigInteger().toString(16)
							.toUpperCase());
				}
				curveOrder.setText(keyPair.getPrivateKey().getParams().getN()
						.toString(16).toUpperCase());
				curveCofactor.setText(keyPair.getPrivateKey().getParams()
						.getH().toString(16).toUpperCase());

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
