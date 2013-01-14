/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 This activity is the first step for verifying a certificate, it offers two
 * ways, X.509 and PGP+ method, the X.509 method will check the certificate
 * against a CRL and using its CA certificate will try to construct the
 * certification path. On the other hand the PGP+ method will use the trust
 * network and a trust list to calculate how much a user could trust in the
 * selected certificate. 
 */
package cinvestav.pki.android.trustednetwork.selection;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CRLController;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.crypto.VerifyPGPActivity;
import cinvestav.pki.android.trustednetwork.crypto.VerifyX509Activity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * 
 * This activity is the first step for verifying a certificate, it offers two
 * ways, X.509 and PGP+ method, the X.509 method will check the certificate
 * against a CRL and using its CA certificate will try to construct the
 * certification path. On the other hand the PGP+ method will use the trust
 * network and a trust list to calculate how much a user could trust in the
 * selected certificate.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class SelectVerificationTypeActivity extends SherlockFragmentActivity {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	SelectVerificationMethodCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	ViewPager mViewPager;

	static final int MENU_NEXT = 0;
	public static final String EXTRA_CERTIFICATE_ID = "EXTRA_SELECTED_CERTIFICATE_ID";
	public static final String EXTRA_CURRENT_OPERATION = "EXTRA_CURRENT_OPERATION";
	public static final int SIGN = 0;
	public static final int VERIFY = 1;

	static SubjectController subjectController;
	static TrustedCertificateController trustedCertificateController;
	static CRLController crlController;
	static CertificateController certificateController;

	private int current_option;
	private int selectedCertificateId;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if (subjectController == null) {
			subjectController = new SubjectController(getApplicationContext());
		}
		if (trustedCertificateController == null) {
			trustedCertificateController = new TrustedCertificateController(
					getApplicationContext());
		}

		if (crlController == null) {
			crlController = new CRLController(getApplicationContext());
		}

		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.detail_collection);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_cert_verification_type);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new SelectVerificationMethodCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
		selectedCertificateId = this.getIntent().getExtras()
				.getInt(EXTRA_CERTIFICATE_ID);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for "next" menu option.
		MenuItem itemAdd_key = menu.add(0, MENU_NEXT, 0, R.string.menu_next);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();
			return true;
		case MENU_NEXT:
			goToNext();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Go to the next activity of the verification task, this method will check
	 * if a list has been selected
	 */
	public void goToNext() {
		int page = mViewPager.getCurrentItem();
		Intent intent;
		switch (page) {
		case SelectVerificationMethodCollectionPagerAdapter.PGP_PAGE:
			Integer selectedOwnerId = ((SelectVerificationMethodCollectionPagerAdapter) mViewPager
					.getAdapter()).getTrustListFragment()
					.getSelectedSubjectId();

			if (selectedOwnerId == 0) {
				Toast.makeText(this, R.string.error_empty_list_owner,
						Toast.LENGTH_LONG).show();
				return;
			}

			intent = new Intent(this, VerifyPGPActivity.class);

			intent.putExtra(VerifyPGPActivity.EXTRA_TRUST_LIST_OWNER_ID,
					selectedOwnerId);
			intent.putExtra(EXTRA_CERTIFICATE_ID, selectedCertificateId);
			intent.putExtra(EXTRA_CURRENT_OPERATION, getIntent().getExtras()
					.getInt(EXTRA_CURRENT_OPERATION));
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			startActivity(intent);

			break;
		case SelectVerificationMethodCollectionPagerAdapter.X509_PAGE:
			Integer selectedCRLId = ((SelectVerificationMethodCollectionPagerAdapter) mViewPager
					.getAdapter()).getCRLListFragment().getSelectedCRLId();

			if (selectedCRLId == 0) {
				Toast.makeText(this, R.string.error_empty_crl,
						Toast.LENGTH_LONG).show();
				return;
			}
			
			intent = new Intent(this, VerifyX509Activity.class);

			intent.putExtra(VerifyX509Activity.EXTRA_CRL_ID,
					selectedCRLId);
			intent.putExtra(EXTRA_CERTIFICATE_ID, selectedCertificateId);
			intent.putExtra(EXTRA_CURRENT_OPERATION, getIntent().getExtras()
					.getInt(EXTRA_CURRENT_OPERATION));
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			startActivity(intent);

			break;
		default:
			break;
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {

		// if (verifyCertificateECKeyTask != null) {
		// verifyCertificateECKeyTask.cancel(true);
		// }

		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent;
		upIntent = new Intent(this, PKITrustNetworkActivity.class);
		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				current_option);

		if (NavUtils.shouldUpRecreateTask(this, upIntent)) {
			// This activity is not part of the application's task, so
			// create a new task
			// with a synthesized back stack.
			TaskStackBuilder.create(this)
			// If there are ancestor activities, they should be added here.
					.addNextIntent(upIntent).startActivities();
			finish();
		} else {
			// This activity is part of the application's task, so simply
			// navigate up to the hierarchical parent activity.
			NavUtils.navigateUpTo(this, upIntent);
		}
	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment pager that will contains two pages,one for certificates list and
	 * the other for key list
	 */
	public class SelectVerificationMethodCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		SelectTrustListFragment trustListFragment;
		SelectCRLListFragment cRLListFragment;
		private final FragmentManager mFragmentManager;

		private static final int X509_PAGE = 1;
		private static final int PGP_PAGE = 0;

		/**
		 * @return the fragmentSignersList
		 */
		public SelectTrustListFragment getTrustListFragment() {
			return trustListFragment;
		}

		/**
		 * @return the resultFragment
		 */
		public SelectCRLListFragment getCRLListFragment() {
			return cRLListFragment;
		}

		public SelectVerificationMethodCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		@Override
		public Fragment getItem(int i) {
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM " + i);
			// Chose between the two availably: Owner or key
			switch (i) {
			case X509_PAGE:
				if (cRLListFragment == null) {
					cRLListFragment = SelectCRLListFragment.newInstance(
							crlController, certificateController);
				}
				return cRLListFragment;

			case PGP_PAGE:
				if (trustListFragment == null) {
					trustListFragment = SelectTrustListFragment.newInstance(
							subjectController, trustedCertificateController);
				}
				return trustListFragment;

			}

			return new SelectCRLListFragment();
		}

		@Override
		public int getCount() {
			// Total of pages
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case X509_PAGE:
				return getResources()
						.getString(R.string.detail_title_x509_type);
			case PGP_PAGE:
				return getResources().getString(R.string.detail_title_pgp_type);
			default:
				return "";
			}

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.view.PagerAdapter#getItemPosition(java.lang.Object
		 * )
		 */
		@Override
		public int getItemPosition(Object object) {
			// ViewPager uses the getItemPosition() abstract method to check
			// which pages should be destroyed and which should be kept. The
			// default implementation of this function always returns
			// POSITION_UNCHANGED, which causes ViewPager to keep all current
			// pages, and consequently not attaching your new page. Thus, to
			// make fragment replacement work, getItemPosition() needs to be
			// overridden in your adapter and must return POSITION_NONE when
			// called with an old, to be hidden, fragment as argument.
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM POS " + object);

			return POSITION_UNCHANGED;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.FragmentStatePagerAdapter#restoreState(android
		 * .os.Parcelable, java.lang.ClassLoader)
		 */
		@Override
		public void restoreState(Parcelable state, ClassLoader loader) {
			super.restoreState(state, loader);
			if (state != null) {
				Bundle bundle = (Bundle) state;
				Iterable<String> keys = bundle.keySet();
				for (String key : keys) {
					if (key.startsWith("f")) {
						Fragment f = mFragmentManager.getFragment(bundle, key);
						if (f instanceof SelectCRLListFragment) {
							cRLListFragment = (SelectCRLListFragment) f;
						} else if (f instanceof SelectTrustListFragment) {
							trustListFragment = (SelectTrustListFragment) f;
						}

					}
				}
			}

		}

	}
}
