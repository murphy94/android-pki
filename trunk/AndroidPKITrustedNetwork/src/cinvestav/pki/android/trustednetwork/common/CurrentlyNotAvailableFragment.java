/**
 *  Created on  : 25/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, this fragment only displays a
 * message saying that the fragment is not available
 */
package cinvestav.pki.android.trustednetwork.common;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, this fragment only displays a
 * message saying that the fragment is not available
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 25/09/2012
 * @version 1.0
 */
public class CurrentlyNotAvailableFragment extends SherlockFragment {

	public CurrentlyNotAvailableFragment() {
		super();
	}

	public static CurrentlyNotAvailableFragment newInstance() {
		CurrentlyNotAvailableFragment f = new CurrentlyNotAvailableFragment();
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(
				R.layout.currently_not_available_fragment, container, false);

		setRetainInstance(true);

		return rootView;
	}
}
