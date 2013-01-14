/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, this fragment will be added as
 * a page for a viewpager and displays the advanced key options like: Digest
 * Algorithm, encoding type, PKCS options
 */
package cinvestav.pki.android.trustednetwork.add;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, this fragment will be added as
 * a page for a viewpager and displays the advanced key options like: Digest
 * Algorithm, encoding type, PKCS options
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class AddNewKeyAdvancedInformationFragment extends SherlockFragment {
	Spinner spinnerDigest;
	Spinner spinnerEncoding;

	public AddNewKeyAdvancedInformationFragment() {
		super();
	}

	public static AddNewKeyAdvancedInformationFragment newInstance() {
		AddNewKeyAdvancedInformationFragment f = new AddNewKeyAdvancedInformationFragment();
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.add_key_fragment_advanced,
				container, false);

		spinnerDigest = (Spinner) rootView.findViewById(R.id.spinnerDigest);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getActivity(), R.array.digestFunctionArray,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerDigest.setAdapter(adapter);

		spinnerEncoding = (Spinner) rootView
				.findViewById(R.id.spinnerIDEncoding);
		adapter = ArrayAdapter.createFromResource(getActivity(),
				R.array.encodingArray, android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerEncoding.setAdapter(adapter);

		return rootView;
	}
}
