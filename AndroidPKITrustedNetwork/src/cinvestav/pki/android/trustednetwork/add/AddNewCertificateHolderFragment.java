/**
 *  Created on  : 27/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, this fragment will allow 
 * insert all the information referent to the certificate owner, this
 * information will be added dynamically so initially this fragment will only
 * contain a spinner with all the possible fields and the user will add the
 * desired fields by selecting the field name and adding it, next a value should
 * be inserted for that field.
 */
package cinvestav.pki.android.trustednetwork.add;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, this fragment will allow insert
 * all the information referent to the certificate owner, this information will
 * be added dynamically so initially this fragment will only contain a spinner
 * with all the possible fields and the user will add the desired fields by
 * selecting the field name and adding it, next a value should be inserted for
 * that field.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 27/09/2012
 * @version 1.0
 */
public class AddNewCertificateHolderFragment extends SherlockFragment {

	private Spinner spinnerHolderPropertyField;
	private Integer currentId;
	private ArrayAdapter<CharSequence> adapter;
	private HashMap<String, EditText> certificateInformationMap;
	private HashMap<String, String> initialCertificateInformationMap;
	private Boolean loadValues;

	public AddNewCertificateHolderFragment() {
		super();
	}

	public static AddNewCertificateHolderFragment newInstance() {
		AddNewCertificateHolderFragment f = new AddNewCertificateHolderFragment();
		f.setLoadValues(Boolean.FALSE);
		return f;
	}

	public static AddNewCertificateHolderFragment newInstance(
			HashMap<String, String> initialCertificateInformationMap) {
		AddNewCertificateHolderFragment f = new AddNewCertificateHolderFragment();
		f.setInitialCertificateInformationMap(initialCertificateInformationMap);
		f.setLoadValues(Boolean.TRUE);
		return f;
	}

	/**
	 * @param initialCertificateInformationMap
	 *            the initialCertificateInformationMap to set
	 */
	public void setInitialCertificateInformationMap(
			HashMap<String, String> initialCertificateInformationMap) {
		this.initialCertificateInformationMap = initialCertificateInformationMap;
	}

	/**
	 * @param loadValues
	 *            the loadValues to set
	 */
	public void setLoadValues(Boolean loadValues) {
		this.loadValues = loadValues;
	}

	/**
	 * @return the certificateInformationMap
	 */
	public HashMap<String, EditText> getCertificateInformationMap() {
		return certificateInformationMap;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(
				R.layout.add_certificate_holder_fragment, container, false);

		spinnerHolderPropertyField = (Spinner) rootView
				.findViewById(R.id.spinnerAddHolderFieldName);

		adapter = new ArrayAdapter<CharSequence>(getActivity(),
				android.R.layout.simple_spinner_item);

		final LinearLayout layout = (LinearLayout) rootView
				.findViewById(R.id.layoutHolderFields);

		// Fill the adapter
		Iterator<Entry<String, String>> it = CertificateInformationKeys.KEY_NAME_STR_LOOK_UP
				.entrySet().iterator();
		while (it.hasNext()) {
			Entry<String, String> pair = it.next();
			// If the language is ES = Spanish add the Spanish values,
			// otherwise add the English ones
			if (PKITrustNetworkActivity.LAN.equalsIgnoreCase("ES")) {
				if (pair.getKey().contains("_ES")
						&& !CertificateInformationKeys.CUSTOM_EXTENSION
								.contains(pair.getKey().replace("_ES", ""))) {
					adapter.add(pair.getValue());
				}
			} else {
				if (!pair.getKey().contains("_ES")
						&& !CertificateInformationKeys.CUSTOM_EXTENSION
								.contains(pair.getKey())) {
					adapter.add(pair.getValue());
				}
			}

		}

		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerHolderPropertyField.setAdapter(adapter);

		TextView addNewField = (TextView) rootView
				.findViewById(R.id.lblImgAddNewHolderField);

		// If the certificateInformap is null, create a new one
		if (certificateInformationMap == null) {
			currentId = addNewField.getId();
			certificateInformationMap = new HashMap<String, EditText>();
		} else {
			// If its not null, add all the entries to the list layout
			loadFields(layout);
		}

		addNewField.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				// TODO REMOVE "TEST VALUE"!!! ONLY FOR TESTING PURPOSES
				onClickAddNewField(spinnerHolderPropertyField.getSelectedItem()
						+ "", "", layout);
			}
		});

		if (loadValues) {
			// Change the value so this will only will be made the first time
			// the view is loaded
			loadValues = Boolean.FALSE;

			if (initialCertificateInformationMap.size() > 0) {
				Iterator<Entry<String, String>> i = initialCertificateInformationMap
						.entrySet().iterator();

				while (i.hasNext()) {
					Entry<String, String> entry = i.next();
					String fieldName = CertificateInformationKeys
							.getKeyNameStr(entry.getKey(),
									PKITrustNetworkActivity.LAN);
					String fieldValue = entry.getValue().toString();
					onClickAddNewField(fieldName, fieldValue, layout);
				}
			}
		}

		return rootView;
	}

	/**
	 * Add all the certificateInformationMap fields to the layout, this will
	 * also remove the field from the adapter
	 * 
	 * @param layout
	 *            To which the fields will be added
	 */
	public void loadFields(LinearLayout layout) {

		if (certificateInformationMap.size() > 0) {
			Iterator<Entry<String, EditText>> i = certificateInformationMap
					.entrySet().iterator();

			LinearLayout layoutAux = (LinearLayout) certificateInformationMap
					.get(certificateInformationMap.keySet().iterator().next())
					.getParent();
			layoutAux.removeAllViews();

			while (i.hasNext()) {
				Entry<String, EditText> entry = i.next();
				String fieldName = entry.getKey().toString();
				String fieldValue = entry.getValue().getText().toString();
				onClickAddNewField(fieldName, fieldValue, layout);
			}
		}
	}

	/**
	 * OnClick listener for the Add new Owner image, add the owner to the data
	 * base, if this owner does not exist in it
	 * 
	 * @param fieldName
	 *            Field name to be added to the view
	 */
	public void onClickAddNewField(final String fieldName, String fieldValue,
			LinearLayout layout) {

		LinearLayout.LayoutParams lpLbl = new LinearLayout.LayoutParams(
				RelativeLayout.LayoutParams.WRAP_CONTENT,
				RelativeLayout.LayoutParams.WRAP_CONTENT);
		lpLbl.setMargins(15, 0, 0, 0);

		TextView newLblTextView = new TextView(getActivity());
		newLblTextView.setLayoutParams(lpLbl);
		newLblTextView.setId(currentId + 1);
		newLblTextView.setText(fieldName);
		newLblTextView.setTextSize(15);
		newLblTextView.setTypeface(null, Typeface.BOLD);
		newLblTextView.setGravity(Gravity.CENTER);
		newLblTextView.setCompoundDrawablesWithIntrinsicBounds(getResources()
				.getDrawable(R.drawable.ic_action_delete), null, null, null);
		newLblTextView.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				Log.i(PKITrustNetworkActivity.TAG, "ON VIEW CLICK: " + v);
				certificateInformationMap.remove(fieldName);
				adapter.add(fieldName);
				LinearLayout parent = (LinearLayout) v.getParent();
				Log.i(PKITrustNetworkActivity.TAG, "Parent: " + parent);
				parent.removeView(v);
				parent.removeView(parent.findViewById(v.getId() + 1));
			}
		});
		layout.addView(newLblTextView);
		currentId = newLblTextView.getId();

		LinearLayout.LayoutParams lpTxt = new LinearLayout.LayoutParams(
				RelativeLayout.LayoutParams.WRAP_CONTENT,
				RelativeLayout.LayoutParams.WRAP_CONTENT);
		lpTxt.setMargins(25, 0, 0, 0);

		EditText newTextView = new EditText(getActivity());
		newTextView.setLayoutParams(lpTxt);
		newTextView.setId(currentId + 1);
		newTextView.setTextSize(15);
		newTextView.setWidth(200);
		newTextView.setText(fieldValue);
		layout.addView(newTextView);
		currentId = newTextView.getId();

		certificateInformationMap.put(fieldName, newTextView);
		adapter.remove(fieldName);
	}
}
