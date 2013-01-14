/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, displays the fields that are necesary for creating a new key
 * like: key type, size, curve name, password
 */
package cinvestav.pki.android.trustednetwork.add;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.ViewFlipper;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, displays the fields that are
 * necesary for creating a new key like: key type, size, curve name, password
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class AddNewKeyInformationFragment extends SherlockFragment {
	Spinner spinnerKeyType;
	//Spinner spinnerECField;
	Spinner spinnerECCurve;
	ViewFlipper vf;
	private LinearLayout mLinearLayout;

	public AddNewKeyInformationFragment() {
		super();
	}

	public static AddNewKeyInformationFragment newInstance() {
		AddNewKeyInformationFragment f = new AddNewKeyInformationFragment();
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.add_key_fragment_key,
				container, false);

		vf = (ViewFlipper) rootView.findViewById(R.id.flipperType);

		spinnerKeyType = (Spinner) rootView.findViewById(R.id.spinnerKeyType);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getActivity(), R.array.keyTypeArray,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerKeyType.setAdapter(adapter);
		spinnerKeyType
				.setOnItemSelectedListener(new KeyTypeSpinnerItemSelectedListener());

		/*spinnerECField = (Spinner) rootView.findViewById(R.id.spinnerECField);
		adapter = ArrayAdapter.createFromResource(getActivity(),
				R.array.ecFieldArray, android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerECField.setAdapter(adapter);
		spinnerECField
				.setOnItemSelectedListener(new ECFieldSpinnerItemSelectedListener());*/

		spinnerECCurve = (Spinner) rootView.findViewById(R.id.spinnerECCurve);
		adapter = ArrayAdapter.createFromResource(getActivity(),
				R.array.ecCurvePrimeArray,
				android.R.layout.simple_spinner_item);
		adapter
				.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerECCurve.setAdapter(adapter);
		
		mLinearLayout = (LinearLayout) rootView.findViewById(R.id.linearLayout_focus);

		return rootView;
	}

	/**
	 * Item Selection Listener for Key Type spinner, should change the view
	 * flipper to set the fragment that contains the corresponding fields of the
	 * selected key type
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 10/09/2012
	 * @version 1.0
	 */
	public class KeyTypeSpinnerItemSelectedListener implements
			OnItemSelectedListener {

		public void onItemSelected(AdapterView<?> parent, View v, int pos,
				long id) {
			// Set the ViewFlipper Animation
			vf.setAnimation(AnimationUtils.loadAnimation(getActivity(),
					R.anim.fragment_slide_left_enter));
			// Change the view according the key type (RSA or EC)
			vf.setDisplayedChild(pos);
		}

		public void onNothingSelected(AdapterView<?> arg0) {
			// TODO Auto-generated method stub

		}

	}

	public class ECFieldSpinnerItemSelectedListener implements
			OnItemSelectedListener {
		/**
		 * This is called when an item in ECFieldSpinner is selected, so the
		 * ECCurveSpinner adapter should be changed according the selection
		 */
		public void onItemSelected(AdapterView<?> parent, View v, int pos,
				long id) {

			ArrayAdapter<CharSequence> adapterCurve;
			// If field prime is selected
			if (pos == 0) {
				adapterCurve = ArrayAdapter.createFromResource(getActivity(),
						R.array.ecCurvePrimeArray,
						android.R.layout.simple_spinner_item);
				adapterCurve
						.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
				spinnerECCurve.setAdapter(adapterCurve);

			} else if (pos == 1) {
				// If field binary is selected
				adapterCurve = ArrayAdapter.createFromResource(getActivity(),
						R.array.ecCurveBinaryArray,
						android.R.layout.simple_spinner_item);

				adapterCurve
						.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
				spinnerECCurve.setAdapter(adapterCurve);
			}

		}

		public void onNothingSelected(AdapterView<?> arg0) {
			// TODO Auto-generated method stub

		}

	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.Fragment#onResume()
	 */
	@Override
	public void onResume() {

		super.onResume();
		// do not give the editbox focus automatically when activity starts
		//txtNewOwnerName.clearFocus();
		mLinearLayout.requestFocus();

	}

}
