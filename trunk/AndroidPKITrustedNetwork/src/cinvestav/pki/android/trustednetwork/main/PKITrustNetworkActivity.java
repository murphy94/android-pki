/**
 *  Created on  : 20/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This is the main activity of the PKI Trust Network, this activity include all the tabs
 *  for the application, extends from SherlockFragmentActivity so an action bar could be added 
 *  and the tabs include swipe gesture in order to change between them.
 *  	
 */

package cinvestav.pki.android.trustednetwork.main;

import java.io.IOException;
import java.util.Locale;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings.Secure;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.util.SparseArray;
import android.widget.Toast;
import cinvestav.android.pki.db.db.DataBaseHelper;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.ActionBar.Tab;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * This is the main activity of the PKI Trust Network, this activity include all
 * the tabs for the application, extends from SherlockFragmentActivity so an
 * action bar could be added and the tabs include swipe gesture in order to
 * change between them.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 20/08/2012
 * @version 1.0
 */
public class PKITrustNetworkActivity extends SherlockFragmentActivity implements
		ActionBar.TabListener {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments for each of the three primary sections of the app. We use a
	 * {@link android.support.v4.app.FragmentPagerAdapter} derivative, which
	 * will keep every loaded fragment in memory. If this becomes too memory
	 * intensive, it may be best to switch to a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter}.
	 */
	AppSectionsPagerAdapter mAppSectionsPagerAdapter;

	private SparseArray<String> TITLES;
	private static final Integer KEY_FRAGMENT = 0;
	private static final Integer CERTIFICATE_FRAGMENT = 1;
	private static final Integer TRUST_NETWORK_FRAGMENT = 2;
	private static final Integer CRL_FRAGMENT = 3;
	private static final Integer SECURE_FRAGMENT = 4;
	private static final Integer SETTINGS_FRAGMENT = 5;

	public static final String CURRENT_OPTION = "CURRENT_OPTION";
	public static final String EXTRA_NEXT_OPERATION = "EXTRA_NEXT_OPERATION";
	
	public static final int KEY = 0;
	public static final int CERTIFICATE = 1;
	public static final int TRUST_NETWORK = 2;
	public static final int CRL = 3;

	public static final int DECIPHER = 5;
	public static final int VERIFY = 4;
	public static final int CIPHER = 3;
	public static final int SIGN = 2;
	public static final int IMPORT = 1;
	public static final int ADD = 0;

	public static final String TAG = "ANDROID_PKI_TRUST_NETWORK";
	public static final String LAN = Locale.getDefault().getLanguage();
	public static String ANDROID_ID;

	/**
	 * The {@link ViewPager} that will display the three primary sections of the
	 * app, one at a time.
	 */
	ViewPager mViewPager;

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		
		int selectedTab = getIntent().getIntExtra(CURRENT_OPTION, 0);

		// Loads the data base
		initDBLoader(this);
		fillSubtitlesArray();
		// Create the adapter that will return a fragment for each of the three
		// primary sections
		// of the app.
		mAppSectionsPagerAdapter = new AppSectionsPagerAdapter(
				getSupportFragmentManager());

		// Get a unique device ID value;
		ANDROID_ID = Secure.getString(this.getContentResolver(),
				Secure.ANDROID_ID);
		Log.i(TAG, "ANDROID_ID: " + ANDROID_ID);

		// Set up the action bar.
		final ActionBar ab = getSupportActionBar();
		// ab.setDisplayHomeAsUpEnabled(Boolean.TRUE);
		ab.setSubtitle(TITLES.get(KEY_FRAGMENT));
		ab.setDisplayShowTitleEnabled(true);

		// Set up the ViewPager, attaching the adapter and setting up a listener
		// for when the user swipes between sections.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mAppSectionsPagerAdapter);
		mViewPager
				.setOnPageChangeListener(new ViewPager.SimpleOnPageChangeListener() {
					@Override
					public void onPageSelected(int position) {
						// When swiping between different app sections, select
						// the corresponding tab.
						// We can also use ActionBar.Tab#select() to do this if
						// we have a reference to the
						// Tab.
						ab.setSubtitle(TITLES.get(position));
						ab.setSelectedNavigationItem(position);
					}
				});

		ab.addTab(ab.newTab().setText("").setIcon(R.drawable.ic_menu_keys)
				.setTabListener(this));
		ab.addTab(ab.newTab().setText("").setIcon(R.drawable.ic_menu_cert)
				.setTabListener(this));
		ab.addTab(ab.newTab().setText("")
				.setIcon(R.drawable.ic_menu_trust_network).setTabListener(this));
		ab.addTab(ab.newTab().setText("").setIcon(R.drawable.ic_menu_crl)
				.setTabListener(this));

		// default to tab navigation
		showTabsNav();
		ab.setSelectedNavigationItem(selectedTab);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		Intent intent;
		switch (item.getItemId()) {
		case android.R.id.home:
			// TODO handle clicking the app icon/logo
			return false;
		case R.id.menu_secure:
			// Show Secure options Fragment
			intent = new Intent(this, SecureSectionActivity.class);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION, mViewPager.getCurrentItem());
			startActivity(intent);
			return true;
		/*case R.id.menu_settings:
			// Show Settings Fragment
			intent = new Intent(this, SettingsSectionActivity.class);
			startActivity(intent);
			return true;*/
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	private void showTabsNav() {
		ActionBar ab = getSupportActionBar();
		if (ab.getNavigationMode() != ActionBar.NAVIGATION_MODE_TABS) {
			ab.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);
		}
	}

	/**
	 * Fills the subtitle array with the resource strings, so it would be
	 * multilanguage
	 */
	private void fillSubtitlesArray() {
		TITLES = new SparseArray<String>();
		TITLES.put(KEY_FRAGMENT,
				getResources().getString(R.string.subtitle_keys));
		TITLES.put(CERTIFICATE_FRAGMENT,
				getResources().getString(R.string.subtitle_cert));
		TITLES.put(TRUST_NETWORK_FRAGMENT,
				getResources().getString(R.string.subtitle_trust_network));
		TITLES.put(CRL_FRAGMENT, getResources()
				.getString(R.string.subtitle_crl));
		TITLES.put(SECURE_FRAGMENT,
				getResources().getString(R.string.subtitle_secure));
		TITLES.put(SETTINGS_FRAGMENT,
				getResources().getString(R.string.subtitle_settings));

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getSupportMenuInflater().inflate(R.menu.main_menu, menu);

		return super.onCreateOptionsMenu(menu);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.actionbarsherlock.app.ActionBar.TabListener#onTabSelected(com.
	 * actionbarsherlock.app.ActionBar.Tab,
	 * android.support.v4.app.FragmentTransaction)
	 */
	@Override
	public void onTabSelected(Tab tab, FragmentTransaction ft) {
		// When the given tab is selected, switch to the corresponding page in
		// the ViewPager.
		mViewPager.setCurrentItem(tab.getPosition());

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.actionbarsherlock.app.ActionBar.TabListener#onTabUnselected(com.
	 * actionbarsherlock.app.ActionBar.Tab,
	 * android.support.v4.app.FragmentTransaction)
	 */
	@Override
	public void onTabUnselected(Tab tab, FragmentTransaction ft) {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.actionbarsherlock.app.ActionBar.TabListener#onTabReselected(com.
	 * actionbarsherlock.app.ActionBar.Tab,
	 * android.support.v4.app.FragmentTransaction)
	 */
	@Override
	public void onTabReselected(Tab tab, FragmentTransaction ft) {
		// TODO Auto-generated method stub

	}

	/**
	 * A {@link FragmentPagerAdapter} that returns a fragment corresponding to
	 * one of the primary sections of the app.
	 */
	public class AppSectionsPagerAdapter extends FragmentStatePagerAdapter {

		public AppSectionsPagerAdapter(FragmentManager fm) {
			super(fm);
		}

		@Override
		public Fragment getItem(int i) {
			switch (i) {
			case 0:
				// Fragment of the app is the Key Management.
				return new KeyManagementSectionFragment();
			case 1:
				// Fragment of the app is the Certificate Management.
				return new CertificateManagementSectionFragment();

			case 2:
				// Fragment of the app is the Trust Network Management.
				return new TrustNetworkManagementSectionFragment();

			case 3:
				// Fragment of the app is the CRL Management.
				return new CRLManagementSectionFragment();

			default:
				return new KeyManagementSectionFragment();
			}
		}

		@Override
		public int getCount() {
			return 4;
		}
	}

	private void initDBLoader(Context context) {

		DataBaseHelper myDbHelper;
		myDbHelper = new DataBaseHelper(context);

		try {
			/*
			 * Creates a empty database on the system and rewrites it with your
			 * own database. if the database is already created, do nothing
			 */
			myDbHelper.createDataBase(context.getPackageName());
		} catch (IOException ioe) {
			ioe.printStackTrace();
			Toast.makeText(this, R.string.error_creating_db, Toast.LENGTH_SHORT)
					.show();
		}
	}

}