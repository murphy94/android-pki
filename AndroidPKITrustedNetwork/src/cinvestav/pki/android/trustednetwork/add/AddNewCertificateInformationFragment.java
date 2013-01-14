/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 A fragment representing a section of the app, this fragment will allow the
 * user to insert the certificate relevant information like, validity period,
 * key usage, constrains among others. This fragment could be used for creating
 * a new certificate or signing a existing one, in case of creating a new one
 * the view will be empty by default, on the other hand for signing a existing
 * certificate the fragment will pre-load the certificate fields into the view
 */
package cinvestav.pki.android.trustednetwork.add;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.Spinner;
import android.widget.TextView;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.DatePickerFragment;
import cinvestav.pki.android.trustednetwork.common.DatePickerFragment.OnDataSetListener;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, this fragment will allow the
 * user to insert the certificate relevant information like, validity period,
 * key usage, constrains among others. This fragment could be used for creating
 * a new certificate or signing a existing one, in case of creating a new one
 * the view will be empty by default, on the other hand for signing a existing
 * certificate the fragment will pre-load the certificate fields into the view
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 28/09/2012
 * @version 1.0
 */
public class AddNewCertificateInformationFragment extends SherlockFragment {

	private TextView txtNotAfter;
	private TextView txtNotBefore;
	private Spinner spinnerSignAlgorithmName;
	private Spinner spinnerCertificateType;
	private Date initialNotAfter;
	private Date initialNotBefore;
	private List<Integer> initialKeyUsageList;
	private Boolean loadValues;

	Integer keyType;

	private java.text.DateFormat df;

	public AddNewCertificateInformationFragment() {
		super();
	}

	/**
	 * @return the keyType
	 */
	public Integer getKeyType() {
		return keyType;
	}

	/**
	 * @param keyType
	 *            the keyType to set
	 */
	public void setKeyType(Integer keyType) {
		this.keyType = keyType;
	}

	/**
	 * @return the spinnerSignAlgorithmName
	 */
	public Spinner getSpinnerSignAlgorithmName() {
		return spinnerSignAlgorithmName;
	}

	/**
	 * @return the spinnerCertificateType
	 */
	public Spinner getSpinnerCertificateType() {
		return spinnerCertificateType;
	}

	/**
	 * Create a new instance with default values for the view
	 * 
	 * @param keyType
	 *            Key type, will be used for selecting the correct signature
	 *            algorithm name list
	 * @return a new Instance of this object
	 */
	public static AddNewCertificateInformationFragment newInstance(
			Integer keyType) {
		AddNewCertificateInformationFragment f = new AddNewCertificateInformationFragment();
		f.setKeyType(keyType);
		f.setLoadValues(Boolean.FALSE);

		// Set todays date to not Before text and add 1 year for NotAfter by
		// default
		Date today = new Date();
		Calendar date = Calendar.getInstance();
		date.setTime(today);
		date.add(Calendar.YEAR, 1);

		f.setInitialNotAfter(date.getTime());
		f.setInitialNotBefore(today);
		return f;
	}

	/**
	 * Create a new instance with initial values for the view
	 * 
	 * @param keyType
	 *            Key type, will be used for selecting the correct signature
	 *            algorithm name list
	 * @param initialNotAfter
	 *            notAfter text view initial value to be shown
	 * @param initialNotBefore
	 *            notAfter text view initial value to be shown
	 * @param initialKeyUsageList
	 *            List of key usages that should be selected when the view is
	 *            created
	 * @return a new Instance of this object
	 */
	public static AddNewCertificateInformationFragment newInstance(
			Integer keyType, Date initialNotAfter, Date initialNotBefore,
			List<Integer> initialKeyUsageList) {
		AddNewCertificateInformationFragment f = new AddNewCertificateInformationFragment();
		f.setKeyType(keyType);
		f.setInitialNotAfter(initialNotAfter);
		f.setInitialNotBefore(initialNotBefore);
		f.setInitialKeyUsageList(initialKeyUsageList);
		f.setLoadValues(Boolean.TRUE);
		return f;
	}

	/**
	 * @return the loadValues
	 */
	public Boolean getLoadValues() {
		return loadValues;
	}

	/**
	 * @param loadValues
	 *            the loadValues to set
	 */
	public void setLoadValues(Boolean loadValues) {
		this.loadValues = loadValues;
	}

	/**
	 * @param initialNotAfter
	 *            the initialNotAfter to set
	 */
	public void setInitialNotAfter(Date initialNotAfter) {
		this.initialNotAfter = initialNotAfter;
	}

	/**
	 * @param notBefore
	 *            the notBefore to set
	 */
	public void setInitialNotBefore(Date initialNotBefore) {
		this.initialNotBefore = initialNotBefore;
	}

	/**
	 * @param initialKeyUsageList
	 *            the initialKeyUsageList to set
	 */
	public void setInitialKeyUsageList(List<Integer> initialKeyUsageList) {
		this.initialKeyUsageList = initialKeyUsageList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.Fragment#onSaveInstanceState(android.os.Bundle)
	 */
	@Override
	public void onSaveInstanceState(Bundle arg0) {
		try {
			initialNotAfter = df.parse(txtNotAfter.getText().toString());
			initialNotBefore = df.parse(txtNotBefore.getText().toString());
		} catch (ParseException e) {
			e.printStackTrace();
		}

		super.onSaveInstanceState(arg0);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		df = DateFormat.getDateFormat(getActivity().getApplicationContext());
		View rootView = inflater
				.inflate(R.layout.add_certificate_information_fragment,
						container, false);

		setRetainInstance(true);

		final OnDataSetListenerNotAfterImp onDataSetListenerNotAfterImp = new OnDataSetListenerNotAfterImp();
		final OnDataSetListenerNotBeforeImp onDataSetListenerNotBeforeImp = new OnDataSetListenerNotBeforeImp();
		txtNotAfter = (TextView) rootView
				.findViewById(R.id.txtCertificateValidityNotAfter);

		txtNotAfter.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				// create a new dialog fragment
				DialogFragment newFragment;
				try {
					// Gets a new instance of the DatePickerFragment using the
					// actual not after date and create a new DataSetListener
					newFragment = DatePickerFragment.newInstance(
							df.parse(txtNotAfter.getText().toString()),
							onDataSetListenerNotAfterImp);
					newFragment.show(getActivity().getSupportFragmentManager(),
							"datePicker");
				} catch (ParseException e) {
					e.printStackTrace();
				}

			}
		});

		txtNotBefore = (TextView) rootView
				.findViewById(R.id.txtCertificateValidityNotBefore);

		txtNotBefore.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				// create a new dialog fragment
				DialogFragment newFragment;
				try {
					// Gets a new instance of the DatePickerFragment using the
					// actual not after date and create a new DataSetListener
					newFragment = DatePickerFragment.newInstance(
							df.parse(txtNotBefore.getText().toString()),
							onDataSetListenerNotBeforeImp);
					newFragment.show(getActivity().getSupportFragmentManager(),
							"datePicker");
				} catch (ParseException e) {
					e.printStackTrace();
				}

			}
		});

		ArrayAdapter<CharSequence> adapter;
		spinnerSignAlgorithmName = (Spinner) rootView
				.findViewById(R.id.spinnerCertificateSignaturenatureAlgorithm);
		int arrayId;
		// Select the array to show in order of the key type
		if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)
				|| keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			arrayId = R.array.certificateSignAlgorithmRSA;
		} else {
			arrayId = R.array.certificateSignAlgorithmEC;
		}

		adapter = ArrayAdapter.createFromResource(getActivity(), arrayId,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerSignAlgorithmName.setAdapter(adapter);

		spinnerCertificateType = (Spinner) rootView
				.findViewById(R.id.spinnerCertificateType);
		adapter = ArrayAdapter.createFromResource(getActivity(),
				R.array.certificateType, android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerCertificateType.setAdapter(adapter);

		final CheckBox chkCipherOnly = (CheckBox) rootView
				.findViewById(R.id.chkKeyUsageEncipherOnly);
		final CheckBox chkDecipherOnly = (CheckBox) rootView
				.findViewById(R.id.chkKeyUsageDecipherOnly);

		CheckBox chkKeyAgreement = (CheckBox) rootView
				.findViewById(R.id.chkKeyUsageKeyAgreement);
		chkKeyAgreement
				.setOnCheckedChangeListener(new OnCheckedChangeListener() {

					@Override
					public void onCheckedChanged(CompoundButton buttonView,
							boolean isChecked) {
						// If the key agreement CheckBox is checked show the
						// cipher and decipher only CheckBoxes, otherwise
						// uncheck and hide that views
						if (isChecked) {
							chkCipherOnly.setVisibility(View.VISIBLE);
							chkDecipherOnly.setVisibility(View.VISIBLE);
						} else {
							chkCipherOnly.setChecked(false);
							chkCipherOnly.setVisibility(View.GONE);
							chkDecipherOnly.setChecked(false);
							chkDecipherOnly.setVisibility(View.GONE);
						}

					}
				});

		// Check if the view should load its initial values or set the default
		// ones, if loadValues is required it means that this fragment is use
		// for sign a certificate instead of creating a new one
		if (loadValues) {
			txtNotAfter.setText(df.format(initialNotAfter));
			txtNotBefore.setText(df.format(initialNotBefore));

			for (Integer keyUsage : initialKeyUsageList) {
				if (keyUsage.equals(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN)) {
					((CheckBox) rootView.findViewById(R.id.chkKeyUsageCRLSign))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageDataCipher))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageDigitalSignature))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageKeyCertSign))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageKeyCipher))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_NONREPUDIATION)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageNonRepudiation))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_KEY_AGREEMENT)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageKeyAgreement))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageDecipherOnly))
							.setChecked(Boolean.TRUE);
					continue;
				}
				if (keyUsage
						.equals(X509UtilsDictionary.X509_KEYUSAGE_ENCIPHER_ONLY)) {
					((CheckBox) rootView
							.findViewById(R.id.chkKeyUsageEncipherOnly))
							.setChecked(Boolean.TRUE);
					continue;
				}

			}

			// Change the value so this will only will be made the first time
			// the view is loaded
			loadValues = Boolean.FALSE;

		} else {
			if (savedInstanceState == null) {
				txtNotAfter.setText(df.format(initialNotAfter));
				txtNotBefore.setText(df.format(initialNotBefore));
			}
		}

		return rootView;
	}

	/**
	 * Implementation of OnDataSetListener interface defined on
	 * {@link DatePickerFragment} for the not after text view
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 29/09/2012
	 * @version 1.0
	 */
	private class OnDataSetListenerNotAfterImp implements OnDataSetListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see cinvestav.pki.android.trustednetwork.common.DatePickerFragment.
		 * OnDataSetListener#onDataSet(java.util.Date)
		 */
		@Override
		public void onDataSet(Date date) {

			txtNotAfter.setText(df.format(date));

		}

	}

	/**
	 * Implementation of OnDataSetListener interface defined on
	 * {@link DatePickerFragment} for the not before text view
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 29/09/2012
	 * @version 1.0
	 */
	private class OnDataSetListenerNotBeforeImp implements OnDataSetListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see cinvestav.pki.android.trustednetwork.common.DatePickerFragment.
		 * OnDataSetListener#onDataSet(java.util.Date)
		 */
		@Override
		public void onDataSet(Date date) {
			txtNotBefore.setText(df.format(date));
		}

	}
}
