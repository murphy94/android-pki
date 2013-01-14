/**
 *  Created on  : 24/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 * 		This activity makes a certificate verification using the proposed PGP
 * improved method, in which a list a list of possible key signers are compared
 * to a trusted list and using a ranking calculates the trust score of the
 * certificate, in this activity will be shown the verification results using a
 * view pager with two pages, one for showing all the available key signers and
 * its scores in the trust list and the second one for show the total trust
 * score of this certificate 	
 */
package cinvestav.pki.android.trustednetwork.crypto;

import java.util.List;

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
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.add.SignCertificateActivity;
import cinvestav.pki.android.trustednetwork.add.SignTypeCertificateActivity;
import cinvestav.pki.android.trustednetwork.common.CurrentlyNotAvailableFragment;
import cinvestav.pki.android.trustednetwork.crypto.SignersListFragment.NotifyListLoaded;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectVerificationTypeActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * This activity makes a certificate verification using the proposed PGP
 * improved method, in which a list a list of possible key signers are compared
 * to a trusted list and using a ranking calculates the trust score of the
 * certificate, in this activity will be shown the verification results using a
 * view pager with two pages, one for showing all the available key signers and
 * its scores in the trust list and the second one for show the total trust
 * score of this certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/10/2012
 * @version 1.0
 */
public class VerifyPGPActivity extends SherlockFragmentActivity implements
		NotifyListLoaded {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	ResultCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	ViewPager mViewPager;

	static final int MENU_FINISH = 0;
	public static final String EXTRA_TRUST_LIST_OWNER_ID = "EXTRA_CRL_ID";

	private TrustedCertificateController trustedCertificateController;
	private CertificateController certificateController;

	private int selectedCertificateId;

	private CertificateDAO certificate;

	private X509Utils x509Utils;

	/**
	 * Owner of the trust list
	 */
	private Integer ownerId;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		
		if (trustedCertificateController == null) {
			trustedCertificateController = new TrustedCertificateController(
					getApplicationContext());
		}

		
		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		try {
			x509Utils = new X509Utils();
		} catch (CryptoUtilsException e1) {
			e1.printStackTrace();
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
		actionBar.setSubtitle(R.string.subtitle_verification_pgp);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new ResultCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		// Get Selected subject ID
		ownerId = getIntent().getIntExtra(EXTRA_TRUST_LIST_OWNER_ID, 0);

		selectedCertificateId = this.getIntent().getExtras()
				.getInt(SelectVerificationTypeActivity.EXTRA_CERTIFICATE_ID);

		try {
			certificate = certificateController.getById(selectedCertificateId);
			certificateController.getCertificateDetails(certificate);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_certs,
					Toast.LENGTH_LONG).show();
			returnHome();
		}

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for "finish" menu option.
		MenuItem itemAdd_key = menu
				.add(0, MENU_FINISH, 0, R.string.menu_finish);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();
			return true;
		case MENU_FINISH:
			finish();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Close the verification result and return to the corresponding activity,
	 * in order to the operation that was performing before verifying the
	 * certificate
	 */
	public void finish() {
		int currentOperation = this.getIntent().getExtras()
				.getInt(SelectVerificationTypeActivity.EXTRA_CURRENT_OPERATION);

		switch (currentOperation) {
		case SelectVerificationTypeActivity.SIGN:
			Intent intent = new Intent(this, SignTypeCertificateActivity.class);

			intent.putExtra(SignCertificateActivity.EXTRA_CERTIFICATE_ID,
					selectedCertificateId);
			startActivity(intent);
			break;
		case SelectVerificationTypeActivity.VERIFY:
			Intent upIntent = new Intent(getApplicationContext(),
					CertificateDetailsActivity.class);
			upIntent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID,
					certificate.getOwner().getId());
			upIntent.putExtra(
					CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID,
					selectedCertificateId);
			startActivity(upIntent);
			break;
		default:
			returnHome();
			break;
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {

		Integer currentOption = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
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
		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION, currentOption);

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
	public class ResultCollectionPagerAdapter extends FragmentStatePagerAdapter {

		SignersListFragment signersListFragment;
		ResultPGPFragment resultFragment;
		private final FragmentManager mFragmentManager;
		Double totalTrust;
		Boolean shouldUpdate;

		private static final int SIGNERS_PAGE = 1;
		private static final int RESULT_PAGE = 0;

		public ResultCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
			totalTrust = 0.0;
			shouldUpdate = Boolean.FALSE;
		}

		/**
		 * @param totalTrust
		 *            the totalTrust to set
		 */
		public void setTotalTrust(Double totalTrust) {
			this.totalTrust = totalTrust;
		}

		/**
		 * @param shouldUpdate
		 *            the shouldUpdate to set
		 */
		public void setShouldUpdate(Boolean shouldUpdate) {
			this.shouldUpdate = shouldUpdate;
		}

		/**
		 * @return the resultFragment
		 */
		public ResultPGPFragment getResultFragment() {
			return resultFragment;
		}

		/**
		 * @param resultFragment
		 *            the resultFragment to set
		 */
		public void setResultFragment(ResultPGPFragment resultFragment) {
			this.resultFragment = resultFragment;
		}

		@Override
		public Fragment getItem(int i) {
			shouldUpdate = Boolean.FALSE;
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM " + i + " - "
					+ totalTrust);
			// Chose between the correct fragment
			switch (i) {
			case RESULT_PAGE:
				if (resultFragment == null || totalTrust != 0) {
					resultFragment = ResultPGPFragment.newInstance(totalTrust);
				}

				return resultFragment;

			case SIGNERS_PAGE:
				if (signersListFragment == null) {
					signersListFragment = SignersListFragment.newInstance(
							trustedCertificateController,
							certificateController, ownerId, x509Utils,
							certificate, VerifyPGPActivity.this);
				}
				return signersListFragment;

			}
			return new CurrentlyNotAvailableFragment();
		}

		@Override
		public int getCount() {
			// Total of pages
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case SIGNERS_PAGE:
				return getResources().getString(
						R.string.detail_title_pgp_signers);
			case RESULT_PAGE:
				return getResources().getString(
						R.string.detail_title_pgp_result);
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
			if (shouldUpdate) {
				return POSITION_NONE;
			}

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
						if (f instanceof ResultPGPFragment) {
							resultFragment = (ResultPGPFragment) f;
						} else if (f instanceof SignersListFragment) {
							signersListFragment = (SignersListFragment) f;
						}

					}
				}
			}

		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.crypto.SignersListFragment.
	 * NotifyListLoaded#setSignersList(java.util.List)
	 */
	@Override
	public void setSignersList(
			List<TrustedCertificateDAO> trustedCertificatesList) {
		Double totalTrust = 0.0;

		// Get sum up the trust values in the list
		for (TrustedCertificateDAO trustedCert : trustedCertificatesList) {
			totalTrust += trustedCert.getTrustLevel();
		}

		// Calculate an average trust
		if (trustedCertificatesList.size() != 0) {
			totalTrust /= trustedCertificatesList.size();
		}

		Log.i(PKITrustNetworkActivity.TAG, "Total Trust: " + totalTrust);
		((ResultCollectionPagerAdapter) mViewPager.getAdapter())
				.setShouldUpdate(Boolean.TRUE);
		((ResultCollectionPagerAdapter) mViewPager.getAdapter())
				.setTotalTrust(totalTrust);

		((ResultCollectionPagerAdapter) mViewPager.getAdapter())
				.getResultFragment().updateTrustLevel(totalTrust);

	}
}
