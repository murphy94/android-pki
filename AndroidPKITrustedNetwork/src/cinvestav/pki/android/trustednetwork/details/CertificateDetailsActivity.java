/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	In this Fragment activity the Certificate Basic Information  will be shown as a collection, so that using swipe action
 *  the user could navigate in it
 */
package cinvestav.pki.android.trustednetwork.details;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.os.Parcelable;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.add.SignCertificateActivity;
import cinvestav.pki.android.trustednetwork.add.SignTypeCertificateActivity;
import cinvestav.pki.android.trustednetwork.common.CurrentlyNotAvailableFragment;
import cinvestav.pki.android.trustednetwork.details.CertificateBasicInformationFragment.OnClickDetailsListener;
import cinvestav.pki.android.trustednetwork.details.CertificateCustomExtensionsInformationFragment.OnClickCertificateCustomExtensionListener;
import cinvestav.pki.android.trustednetwork.details.CertificateCustomExtensionsPositionFragment.OnClickCertificateExtensionPositionListener;
import cinvestav.pki.android.trustednetwork.details.CertificateExtensionsInformationFragment.OnClickCertificateExtensionListener;
import cinvestav.pki.android.trustednetwork.details.CertificateIssuerInformationFragment.OnClickCertificateIssuerListener;
import cinvestav.pki.android.trustednetwork.details.KeyECObjectFragment.OnClickECDetailsListener;
import cinvestav.pki.android.trustednetwork.details.KeyRSAObjectFragment.OnClickRSADetailsListener;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectVerificationTypeActivity;
import cinvestav.pki.android.trustednetwork.share.ExportCertificateActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockDialogFragment;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;
import com.actionbarsherlock.widget.ShareActionProvider;
import com.google.android.maps.MapView;

/**
 * In this Fragment activity the Certificate Basic Information will be shown as
 * a collection, so that using swipe action the user could navigate in it
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class CertificateDetailsActivity extends SherlockFragmentActivity
		implements
		OnClickDetailsListener,
		cinvestav.pki.android.trustednetwork.details.CertificateDecodedInformationFragment.OnClickCertificateDecodeListener,
		OnClickCertificateIssuerListener, OnClickCertificateExtensionListener,
		OnClickCertificateCustomExtensionListener,
		OnClickCertificateExtensionPositionListener, OnClickECDetailsListener,
		OnClickRSADetailsListener {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	private FragmentStatePagerAdapter certificateCollectionPagerAdapter;

	private ArrayList<Integer> ids;
	private ArrayList<Integer> trustLevels;
	private ArrayList<Integer> trustCertificatesIds;
	private int ownerId;
	private int trustedCertificateId;
	private int trustedListOwnerId;
	private Boolean updateTrustCertificate;
	private int mainSubtitleId;

	private X509Utils x509Utils;

	public static final int MENU_OPTION_TRUST_DELETE = 4;
	public static final int MENU_OPTION_TRUST_LEVEL = 5;
	public static final int MENU_OPTION_TRUST_EXPORT = 6;
	public static final int MENU_OPTION_TRUST_SEND = 7;
	public static final int MENU_OPTION_TRUST_ADD = 8;
	public static final int MENU_OPTION_TRUST_UPDATE = 9;

	public static final String EXTRA_OWNER_ID = "EXTRA_OWNER_ID";
	public static final String EXTRA_LIST_OWNER_ID = "EXTRA_LIST_OWNER_ID";
	public static final String EXTRA_CURRENT_ITEM = "EXTRA_CURRENT_ITEM";
	public static final String EXTRA_CURRENT_CERTIFICATE_ID = "EXTRA_CURRENT_CERTIFICATE_ID";
	public static final String EXTRA_TRUSTED_CERTIFICATE_ID = "EXTRA_TRUSTED_CERTIFICATE_ID";
	public static final String EXTRA_UPDATE_TRUSTED_CERTIFICATE = "EXTRA_UPDATE_TRUSTED_CERTIFICATE";

	private static final String CURRENT_ADAPTER = "CURRENT_ADAPTER";
	private static final String CURRENT_CERTIFICATE = "CURRENT_CERTIFICATE";
	private static final String CURRENT_CERTIFICATE_PAGE = "CURRENT_CERTIFICATE_PAGE";
	private static final String CURRENT_SELECTED_CERTIFICATE = "CURRENT_SELECTED_CERTIFICATE";
	private static final String GPS_LAT = "GPS_LAT";
	private static final String GPS_LON = "GPS_LON";
	private static final int ADAPTER_CERTIFICATE = 0;
	private static final int ADAPTER_DECODED = 1;
	private static final int ADAPTER_EXTENSIONS = 2;
	private static final int ADAPTER_POSITION = 3;

	private CertificateController certificateController;
	private TrustedCertificateController trustedCertificateController;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	private ViewPager mViewPager;

	private DecodeX509CertificateTask decodeX509CertificateTask;

	/**
	 * Decoded Certificate to be shown in the fragment
	 */
	private X509Certificate selectedCertificate;

	private MapView mapView;

	/**
	 * @return the selectedCertificate
	 */
	public X509Certificate getSelectedCertificate() {
		return selectedCertificate;
	}

	/**
	 * @return the mapView
	 */
	public MapView getMapView() {
		return mapView;
	}

	/**
	 * @param selectedCertificate
	 *            the selectedCertificate to set
	 */
	protected void setSelectedCertificate(X509Certificate selectedCertificate) {
		this.selectedCertificate = selectedCertificate;
	}

	/**
	 * @return the x509Utils
	 */
	public X509Utils getX509Utils() {
		return x509Utils;
	}

	private ShareActionProvider mShareActionProvider;

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onCreate(android.os.Bundle)
	 */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		try {
			x509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);

		}

		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		if (trustedCertificateController == null) {
			trustedCertificateController = new TrustedCertificateController(
					getApplicationContext());
		}

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		ownerId = getIntent().getIntExtra(EXTRA_OWNER_ID, 0);

		trustedListOwnerId = getIntent().getIntExtra(EXTRA_LIST_OWNER_ID, 0);

		trustedCertificateId = getIntent().getIntExtra(
				EXTRA_TRUSTED_CERTIFICATE_ID, 0);
		updateTrustCertificate = getIntent().getBooleanExtra(
				EXTRA_UPDATE_TRUSTED_CERTIFICATE, Boolean.FALSE);

		// Current selected item position
		int currentItem = getIntent().getIntExtra(EXTRA_CURRENT_ITEM, 0);

		// Current selected certificate id
		int currentCertificate = getIntent().getIntExtra(
				EXTRA_CURRENT_CERTIFICATE_ID, 0);

		setContentView(R.layout.detail_collection);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret,
		// indicating
		// that touching the
		// button will take the user one step up in the application's
		// hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);

		List<CertificateDAO> certs;
		try {
			// If the trustedCertificateId is different from 0, means that the
			// activity comes from
			// adding a new trusted certificate to an owner list, so only one
			// certificate should be shown
			// in the list
			if (trustedCertificateId == 0) {
				if (trustedListOwnerId == 0) {
					mainSubtitleId = R.string.subtitle_cert_collection;
					certs = certificateController.getByOwnerId(ownerId);
				} else {
					mainSubtitleId = R.string.subtitle_trust_cert_collection;

					List<TrustedCertificateDAO> trustedCerts = trustedCertificateController
							.getBySubjectId(trustedListOwnerId);
					certs = new LinkedList<CertificateDAO>();
					trustLevels = new ArrayList<Integer>(trustedCerts.size());
					trustCertificatesIds = new ArrayList<Integer>(
							trustedCerts.size());
					for (TrustedCertificateDAO trustedCert : trustedCerts) {
						certs.add(trustedCert.getTrustedCertificate());
						trustLevels.add(trustedCert.getTrustLevel());
						trustCertificatesIds.add(trustedCert.getId());
					}
				}
			} else {
				certs = new LinkedList<CertificateDAO>();
				// If the view is for update the trust certificate, load the
				// correct values
				if (updateTrustCertificate) {
					mainSubtitleId = R.string.subtitle_trust_cert_update;
					Log.i(PKITrustNetworkActivity.TAG, "CertId: "
							+ trustedCertificateId + " ListOwnerID: "
							+ trustedListOwnerId);

					Map<String, String[]> filterMap = new HashMap<String, String[]>();
					String[] value = new String[3];

					/*
					 * Establish filter properties
					 */
					// Filter value
					value[0] = trustedListOwnerId + "";
					// Filter type
					value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
					filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

					value = new String[3];

					/*
					 * Establish filter properties
					 */
					// Filter value
					value[0] = trustedCertificateId + "";
					// Filter type
					value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_ID;
					filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_ID,
							value);

					// Check if the certificate is not already in the selected
					// list
					List<TrustedCertificateDAO> trustedCerts = trustedCertificateController
							.getByAdvancedFilter(filterMap);
					trustLevels = new ArrayList<Integer>(trustedCerts.size());
					trustCertificatesIds = new ArrayList<Integer>(
							trustedCerts.size());
					for (TrustedCertificateDAO trustedCert : trustedCerts) {
						certs.add(trustedCert.getTrustedCertificate());
						trustLevels.add(trustedCert.getTrustLevel());
						trustCertificatesIds.add(trustedCert.getId());
					}

				} else {
					mainSubtitleId = R.string.subtitle_trust_cert_add;
					// if its for add a new certificate, load default values
					certs.add(certificateController
							.getById(trustedCertificateId));
					trustLevels = new ArrayList<Integer>(1);
					trustCertificatesIds = new ArrayList<Integer>(1);
					trustLevels.add(0);
					trustCertificatesIds.add(0);
				}
			}
			actionBar.setSubtitle(mainSubtitleId);

			ids = new ArrayList<Integer>(certs.size());
			for (int i = 0; i < certs.size(); i++) {
				if (certs.get(i).getId() == currentCertificate) {
					currentItem = i;
				}
				ids.add(certs.get(i).getId());
			}

			// Create an adapter that when requested, will return a fragment
			// representing an object in the collection.
			// ViewPager and its adapters use support library fragments, so
			// we must use getSupportFragmentManager.
			if (savedInstanceState == null) {
				// If the saved instance is null, create the default
				// CertificateCollectionAdapter
				certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
						getSupportFragmentManager());

			} else {
				// If its not null, check the current adapter before the
				// instance change and reload the correct adapter
				int currentAdapter = savedInstanceState.getInt(CURRENT_ADAPTER);

				// Create an adapter that when requested, will return a fragment
				// representing an object in the collection.
				// ViewPager and its adapters use support library fragments, so
				// we must use getSupportFragmentManager.
				switch (currentAdapter) {
				case ADAPTER_CERTIFICATE:
					certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
							getSupportFragmentManager());
					break;
				case ADAPTER_DECODED:
					certificateCollectionPagerAdapter = new CertificateDecodedCollectionPagerAdapter(
							getSupportFragmentManager(),
							savedInstanceState.getInt(CURRENT_CERTIFICATE));
					selectedCertificate = (X509Certificate) savedInstanceState
							.getSerializable(CURRENT_SELECTED_CERTIFICATE);
					break;
				case ADAPTER_EXTENSIONS:
					certificateCollectionPagerAdapter = new CertificateExtensionsCollectionPagerAdapter(
							getSupportFragmentManager(),
							savedInstanceState.getInt(CURRENT_CERTIFICATE),
							savedInstanceState.getInt(CURRENT_CERTIFICATE_PAGE));
					selectedCertificate = (X509Certificate) savedInstanceState
							.getSerializable(CURRENT_SELECTED_CERTIFICATE);
					break;
				case ADAPTER_POSITION:
					certificateCollectionPagerAdapter = new CertificatePositionCollectionPagerAdapter(
							getSupportFragmentManager(),
							savedInstanceState.getInt(CURRENT_CERTIFICATE),
							savedInstanceState.getInt(CURRENT_CERTIFICATE_PAGE),
							savedInstanceState.getFloat(GPS_LAT),
							savedInstanceState.getFloat(GPS_LON));
					selectedCertificate = (X509Certificate) savedInstanceState
							.getSerializable(CURRENT_SELECTED_CERTIFICATE);
					if (mapView == null) {
						/*
						 * View mMapViewContainer =
						 * LayoutInflater.from(this).inflate(
						 * R.layout.detail_certificate_fragment_position, null);
						 * mapView = (MapView)
						 * mMapViewContainer.findViewById(R.id.mapview);
						 */

						mapView = new MapView(this,
								"0u-HXCh9yfz7O9K7DnYFaruqTOIhqHBL2B4zvPg");
						mapView.setClickable(true);
						mapView.setBuiltInZoomControls(true);
					}
					break;

				default:
					certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
							getSupportFragmentManager());
					break;
				}

			}

			// Set up the ViewPager, attaching the adapter.
			mViewPager = (ViewPager) findViewById(R.id.pager);

			mViewPager.setAdapter(certificateCollectionPagerAdapter);
			mViewPager.setCurrentItem(currentItem);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_certs,
					Toast.LENGTH_LONG).show();
			returnHome();

		}

	}

	@Override
	public void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);

		// In base of the current adapter, save into the instance state
		// different information
		if (mViewPager.getAdapter() instanceof CertificateCollectionPagerAdapter) {
			outState.putInt(CURRENT_ADAPTER, ADAPTER_CERTIFICATE);
		} else if (mViewPager.getAdapter() instanceof CertificateDecodedCollectionPagerAdapter) {
			// If its a CertificateDecodedCollectionPagerAdapter, save the
			// selected certificate position and the adapter type
			outState.putInt(CURRENT_ADAPTER, ADAPTER_DECODED);
			outState.putInt(CURRENT_CERTIFICATE,
					((CertificateDecodedCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
		} else if (mViewPager.getAdapter() instanceof CertificateExtensionsCollectionPagerAdapter) {
			// If its a CertificateExtensionsCollectionPagerAdapter, save the
			// selected certificate position, the certificate details page and
			// the adapter type
			outState.putInt(CURRENT_ADAPTER, ADAPTER_EXTENSIONS);
			outState.putInt(CURRENT_CERTIFICATE,
					((CertificateExtensionsCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
			outState.putInt(CURRENT_CERTIFICATE_PAGE,
					((CertificateExtensionsCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificateDetailsPage());
		} else if (mViewPager.getAdapter() instanceof CertificatePositionCollectionPagerAdapter) {
			// If its a CertificatePositionCollectionPagerAdapter, save the
			// selected certificate position, the certificate details page and
			// the adapter type
			outState.putInt(CURRENT_ADAPTER, ADAPTER_POSITION);
			outState.putInt(CURRENT_CERTIFICATE,
					((CertificatePositionCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
			outState.putInt(CURRENT_CERTIFICATE_PAGE,
					((CertificatePositionCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificateDetailsPage());

			outState.putFloat(GPS_LAT,
					((CertificatePositionCollectionPagerAdapter) mViewPager
							.getAdapter()).getGpsPositionLat());

			outState.putFloat(GPS_LON,
					((CertificatePositionCollectionPagerAdapter) mViewPager
							.getAdapter()).getGpsPositionLon());
		}

		if (selectedCertificate != null) {
			outState.putSerializable(CURRENT_SELECTED_CERTIFICATE,
					selectedCertificate);
		}

	}

	/**
	 * Returns share intent
	 * 
	 * @param filePath
	 *            File that will be shared
	 * @return
	 */
	private Intent getDefaultShareIntent(String filePath) {
		File f = new File(filePath);
		Intent shareIntent = new Intent();
		shareIntent.setAction(Intent.ACTION_SEND);
		shareIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(f));
		shareIntent.setType("text/plain");
		return shareIntent;
	}

	/**
	 * This is called when the Home (Up) button is pressed in the action bar.
	 * Create a simple intent that starts the hierarchical parent activity and
	 * use NavUtils in the Support Package to ensure proper handling of Up.
	 */
	private void returnHome() {
		Intent upIntent;
		upIntent = new Intent(this, PKITrustNetworkActivity.class);
		if (trustedListOwnerId == 0 && trustedCertificateId == 0) {
			upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.CERTIFICATE);
		} else {
			upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.TRUST_NETWORK);
		}
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

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Intent upIntent;
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();

			return true;
		case R.id.menu_cert_sign:
			sign();
			break;
		case R.id.menu_cert_export:
			export();
			break;
		case R.id.menu_cert_share:
			share();
			break;
		case R.id.menu_cert_verify:
			verify();
			break;
		case MENU_OPTION_TRUST_LEVEL:
			updateTrustLevel();
			break;
		case MENU_OPTION_TRUST_DELETE:
			DialogFragment newFragment = MyConfirmationDialogFrament
					.newInstance(R.string.alert_dialog_trust_cert_delete_title);
			newFragment.show(getSupportFragmentManager(), "dialog");
			break;

		case MENU_OPTION_TRUST_ADD:
			addTrustedCertificate();
			break;
		case MENU_OPTION_TRUST_UPDATE:
			updateTrustedCertificate();
			break;
		}
		return super.onOptionsItemSelected(item);
	}

	/**
	 * Depending on the current adapter of the view, get the selected trusted
	 * certificate position
	 * 
	 * @return The currently selected trusted certificate position regardless of
	 *         the current adapter of the view
	 */
	public Integer getSelectedTrustedCertificatePosition() {
		Integer certificatePosition = 0;
		// Depending on the current adapter the method for getting the selected
		// certificate will change
		if (mViewPager.getAdapter() instanceof CertificateCollectionPagerAdapter) {
			// If the adapter is the main adapter, the certificate position is
			// gotten using the view current Item
			certificatePosition = mViewPager.getCurrentItem();
		} else if (mViewPager.getAdapter() instanceof CertificateDecodedCollectionPagerAdapter) {
			// If its a CertificateDecodedCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificatePosition = ((CertificateDecodedCollectionPagerAdapter) mViewPager
					.getAdapter()).getCertificatePosition();
		} else if (mViewPager.getAdapter() instanceof CertificateExtensionsCollectionPagerAdapter) {
			// If its a CertificateExtensionsCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificatePosition = ((CertificateExtensionsCollectionPagerAdapter) mViewPager
					.getAdapter()).getCertificatePosition();
		} else if (mViewPager.getAdapter() instanceof CertificatePositionCollectionPagerAdapter) {
			// If its a CertificatePositionCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificatePosition = ((CertificatePositionCollectionPagerAdapter) mViewPager
					.getAdapter()).getCertificatePosition();
		}
		return certificatePosition;
	}

	/**
	 * Depending on the current adapter of the view, notify that the data set
	 * has changed
	 */
	public void notifyDataSetChanged() {
		// Depending on the current adapter, parse it and set the flat that
		// indicates that the data set has change
		PagerAdapter adapter = mViewPager.getAdapter();
		if (adapter instanceof CertificateCollectionPagerAdapter) {
			((CertificateCollectionPagerAdapter) adapter)
					.setShouldUpdate(Boolean.TRUE);
		} else if (adapter instanceof CertificateDecodedCollectionPagerAdapter) {
			((CertificateDecodedCollectionPagerAdapter) adapter)
					.setShouldUpdate(Boolean.TRUE);
		} else if (adapter instanceof CertificateExtensionsCollectionPagerAdapter) {
			((CertificateExtensionsCollectionPagerAdapter) adapter)
					.setShouldUpdate(Boolean.TRUE);

		} else if (adapter instanceof CertificatePositionCollectionPagerAdapter) {
			((CertificatePositionCollectionPagerAdapter) adapter)
					.setShouldUpdate(Boolean.TRUE);

		}
		adapter.notifyDataSetChanged();
	}

	/**
	 * Depending on the current adapter of the view, get the selected
	 * certificate id
	 * 
	 * @return The currently selected certificate id regardless of the current
	 *         adapter of the view
	 */
	public Integer getSelectedCertificateId() {
		Integer certificateId = 0;
		// Depending on the current adapter the method for getting the selected
		// certificate will change
		if (mViewPager.getAdapter() instanceof CertificateCollectionPagerAdapter) {
			// If the adapter is the main adapter, the certificate position is
			// gotten using the view current Item
			certificateId = ids.get(mViewPager.getCurrentItem());
		} else if (mViewPager.getAdapter() instanceof CertificateDecodedCollectionPagerAdapter) {
			// If its a CertificateDecodedCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificateId = ids
					.get(((CertificateDecodedCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
		} else if (mViewPager.getAdapter() instanceof CertificateExtensionsCollectionPagerAdapter) {
			// If its a CertificateExtensionsCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificateId = ids
					.get(((CertificateExtensionsCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
		} else if (mViewPager.getAdapter() instanceof CertificatePositionCollectionPagerAdapter) {
			// If its a CertificatePositionCollectionPagerAdapter, the
			// certificate position could be gotten from the adapter attribute
			// certificate position
			certificateId = ids
					.get(((CertificatePositionCollectionPagerAdapter) mViewPager
							.getAdapter()).getCertificatePosition());
		}
		return certificateId;
	}

	/**
	 * Begins the certificate verification task
	 */
	public void verify() {
		Intent intent = new Intent(this, SelectVerificationTypeActivity.class);

		Integer certificateId = getSelectedCertificateId();
		intent.putExtra(SelectVerificationTypeActivity.EXTRA_CERTIFICATE_ID,
				certificateId);
		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.CERTIFICATE);
		intent.putExtra(SelectVerificationTypeActivity.EXTRA_CURRENT_OPERATION,
				SelectVerificationTypeActivity.VERIFY);

		startActivity(intent);
	}

	/**
	 * Begins the certificate sign task for the selected certificate
	 */
	public void sign() {
		Intent intent = new Intent(this, SignTypeCertificateActivity.class);

		Integer certificateId = getSelectedCertificateId();
		intent.putExtra(SignCertificateActivity.EXTRA_CERTIFICATE_ID,
				certificateId);
		startActivity(intent);
	}

	/**
	 * Opens the update activity for the selected trusted certificate
	 */
	public void updateTrustLevel() {
		Intent intent;
		intent = new Intent(getApplicationContext(),
				CertificateDetailsActivity.class);
		intent.putExtra(
				CertificateDetailsActivity.EXTRA_TRUSTED_CERTIFICATE_ID,
				getSelectedCertificateId());
		intent.putExtra(CertificateDetailsActivity.EXTRA_LIST_OWNER_ID,
				trustedListOwnerId);
		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.TRUST_NETWORK);

		intent.putExtra(EXTRA_UPDATE_TRUSTED_CERTIFICATE, Boolean.TRUE);

		Log.i(PKITrustNetworkActivity.TAG, "CertId: "
				+ getSelectedCertificateId() + " ListOwnerID: "
				+ trustedListOwnerId);
		startActivity(intent);

	}

	/**
	 * Opens the export activity for the selected certificate
	 */
	public void export() {
		Intent intent = new Intent(this, ExportCertificateActivity.class);

		Integer certificateId = getSelectedCertificateId();
		intent.putExtra(EXTRA_CURRENT_CERTIFICATE_ID, certificateId);
		startActivity(intent);
	}

	/**
	 * Shares the selected certificate using Android Share menu
	 */
	public void share() {
		String fileName = Environment.getExternalStorageDirectory()
				+ "/X509Certificate.pem";

		File f = new File(fileName);
		if (f.exists()) {
			f.delete();
		}
		try {
			if (selectedCertificate == null) {
				Integer certId = getSelectedCertificateId();
				selectedCertificate = x509Utils.decode(certificateController
						.getById(certId).getCertificateStr().getBytes());
			}

			x509Utils.saveCertificate(fileName, selectedCertificate,
					CryptoUtils.ENCODING_PEM);

			/** Setting a share intent */
			mShareActionProvider
					.setShareIntent(getDefaultShareIntent(fileName));
		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_cert_share,
					Toast.LENGTH_LONG).show();
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_cert_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Deletes the selected certificate from the selected trusted list
	 */
	public void deleteTrustedCertificate() {

		Integer trustedCertificatePos = getSelectedTrustedCertificatePosition();
		Integer trustCertificateId = trustCertificatesIds
				.get(trustedCertificatePos);
		try {
			TrustedCertificateDAO trustedCertificate = new TrustedCertificateDAO();
			trustedCertificate.setId(trustCertificateId);
			Log.i(PKITrustNetworkActivity.TAG, "TrustedCertificateId: "
					+ trustCertificateId + " - Position: "
					+ trustedCertificatePos);
			Log.i(PKITrustNetworkActivity.TAG, "DELETE: " + ids);
			trustedCertificateController.delete(trustedCertificate);
			Toast.makeText(getApplicationContext(),
					R.string.msgDeleteTrustedCertificateOK, Toast.LENGTH_LONG)
					.show();

			// Delete certificate from list
			ids.remove(ids.get(trustedCertificatePos));
			// If it was the last one, return home
			if (ids.size() <= 0) {
				returnHome();
			}

			// certificateCollectionPagerAdapter.setShouldUpdate(Boolean.TRUE);
			Log.i(PKITrustNetworkActivity.TAG, "DELETE: " + ids);
			notifyDataSetChanged();

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_trust_cert_add_db,
					Toast.LENGTH_LONG).show();

		}

	}

	/**
	 * Add the selected certificate to the selected trusted list including the
	 * inserted certificate trust level
	 */
	public void addTrustedCertificate() {
		Integer trustLevel = ((CertificateCollectionPagerAdapter) mViewPager
				.getAdapter()).getCertificateTrustLevel();
		// Check that the trust level has a correct value
		if (trustLevel == null) {
			Toast.makeText(this, R.string.error_trust_cert_level,
					Toast.LENGTH_LONG).show();
			return;
		}
		try {
			CertificateDAO cert = certificateController
					.getById(trustedCertificateId);

			Map<String, String[]> filterMap = new HashMap<String, String[]>();
			String[] value = new String[3];

			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = trustedListOwnerId + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
			filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

			value = new String[3];

			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = cert.getId() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_ID;
			filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_ID, value);

			// Check if the certificate is not already in the selected list
			Integer count = trustedCertificateController.getByAdvancedFilter(
					filterMap).size();
			if (count > 0) {
				Toast.makeText(getApplicationContext(),
						R.string.error_trust_cert_duplicate, Toast.LENGTH_LONG)
						.show();
				return;
			}

			TrustedCertificateDAO trustedCertificate = new TrustedCertificateDAO();
			trustedCertificate.setTrustedCertificate(cert);
			trustedCertificate.setTrustLevel(trustLevel);

			trustedCertificateController.insert(trustedCertificate,
					trustedListOwnerId);
			Toast.makeText(getApplicationContext(),
					R.string.msgAddTrustedCertificateOK, Toast.LENGTH_LONG)
					.show();
			returnHome();
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_trust_cert_add_db,
					Toast.LENGTH_LONG).show();

		}

	}

	/**
	 * Updates the trust level in the selected trusted certificate
	 */
	public void updateTrustedCertificate() {
		Integer trustLevel = ((CertificateCollectionPagerAdapter) mViewPager
				.getAdapter()).getCertificateTrustLevel();

		// Check that the trust level has a correct value
		if (trustLevel == null) {
			Toast.makeText(this, R.string.error_trust_cert_level,
					Toast.LENGTH_LONG).show();
			return;
		}
		try {

			TrustedCertificateDAO trustedCertificate = trustedCertificateController
					.getById(trustCertificatesIds.get(0));

			trustedCertificate.setTrustLevel(trustLevel);
			trustedCertificateController.update(trustedCertificate);
			Toast.makeText(getApplicationContext(),
					R.string.msgUpdateTrustedCertificateOK, Toast.LENGTH_LONG)
					.show();

			returnHome();
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_trust_cert_update_db,
					Toast.LENGTH_LONG).show();

		}

	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment representing an object in the collection.
	 */
	public class CertificateCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		Fragment certificateFragment;
		Boolean shouldUpdate;
		private final FragmentManager mFragmentManager;

		public CertificateCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		/**
		 * @return the certificateFragment
		 */
		public Fragment getCertificateFragment() {
			return certificateFragment;
		}

		/**
		 * @param certificateFragment
		 *            the certificateFragment to set
		 */
		public void setCertificateFragment(Fragment certificateFragment) {
			this.certificateFragment = certificateFragment;
		}

		public Integer getCertificateTrustLevel() {
			if (certificateFragment instanceof TrustedCertificateBasicInformationFragment) {
				Integer trustLevel = ((TrustedCertificateBasicInformationFragment) certificateFragment)
						.getTrustLevelDB();
				return trustLevel;

			} else {
				return null;
			}
		}

		/**
		 * @param shouldUpdate
		 *            the shouldUpdate to set
		 */
		public void setShouldUpdate(Boolean shouldUpdate) {
			this.shouldUpdate = shouldUpdate;
		}

		@Override
		public Fragment getItem(int i) {
			shouldUpdate = Boolean.FALSE;
			getSupportActionBar().setSubtitle(mainSubtitleId);
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM [" + i + "]");
			selectedCertificate = null;

			// Create a new instance for the fragment, pass the certificate id
			// and the controllers
			if (trustLevels == null) {
				// If trustLevels is null, means that no trust level should be
				// shown
				certificateFragment = CertificateBasicInformationFragment
						.newInstance(ids.get(i), certificateController);
			} else {
				// If trustLevels is not null, means that the trust level should
				// be shown
				// Determines if the trust of the certificate could be edited
				Boolean editable = trustedCertificateId != 0;
				certificateFragment = TrustedCertificateBasicInformationFragment
						.newInstance(ids.get(i), certificateController,
								trustLevels.get(i), editable,
								trustCertificatesIds.get(i));
			}
			return certificateFragment;
		}

		@Override
		public int getCount() {
			// Get the count of certificates
			return ids.size();
		}

		@Override
		public CharSequence getPageTitle(int position) {
			return getResources().getString(R.string.detail_title_certificate)
					+ " " + (position + 1);
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

			// If the id in the current selected item is 0, it means that was
			// deleted, so it should be removed and the pager should be updated
			if (shouldUpdate) {
				Log.i(PKITrustNetworkActivity.TAG, "1 DELETE: " + ids);
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
						if (f instanceof CertificateBasicInformationFragment) {
							certificateFragment = (CertificateBasicInformationFragment) f;
						} else if (f instanceof TrustedCertificateBasicInformationFragment) {
							certificateFragment = (TrustedCertificateBasicInformationFragment) f;
						}

					}
				}
			}
		}

	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment representing an object in the collection. This collection will
	 * have always 4 pages, one for certificate information, one for issuer, one
	 * for owner information and the last one for the public key information
	 */
	public class CertificateDecodedCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		/**
		 * Certificate position in the certificate view pager, to be used as
		 * reference when hide details is selected
		 */
		Integer certificatePosition;
		Boolean shouldUpdate;

		public static final int PUBLIC_KEY_PAGE = 3;
		public static final int OWNER_PAGE = 2;
		public static final int CERTIFICATE_PAGE = 1;
		public static final int ISSUER_PAGE = 0;

		public CertificateDecodedCollectionPagerAdapter(FragmentManager fm,
				Integer certificatePosition) {
			super(fm);
			this.certificatePosition = certificatePosition;
		}

		/**
		 * @return the certificatePosition
		 */
		public Integer getCertificatePosition() {
			return certificatePosition;
		}

		/**
		 * @param certificatePosition
		 *            the certificatePosition to set
		 */
		public void setCertificatePosition(Integer certificatePosition) {
			this.certificatePosition = certificatePosition;
		}

		/**
		 * @param shouldUpdate
		 *            the shouldUpdate to set
		 */
		public void setShouldUpdate(Boolean shouldUpdate) {
			this.shouldUpdate = shouldUpdate;
		}

		@Override
		public Fragment getItem(int i) {
			shouldUpdate = Boolean.FALSE;
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM DECODE [" + i + "]");
			getSupportActionBar().setSubtitle(R.string.subtitle_cert_detail);
			switch (i) {
			case PUBLIC_KEY_PAGE:
				PersonalKeyDAO personalKey = new PersonalKeyDAO();
				try {
					ECPublicKey publicKey = ECPublicKey
							.parse(getSelectedCertificate().getPublicKey());
					personalKey.setKeyType(PersonalKeyDAO.PUBLIC_EC);
					personalKey.setKeyStr(new String(publicKey.encode()));
					return KeyECObjectFragment.newInstance(personalKey);
				} catch (CryptoUtilsException e) {
					try {
						RSAPublicKey publicKey = RSAPublicKey
								.parse(getSelectedCertificate().getPublicKey());
						personalKey.setKeyType(PersonalKeyDAO.PUBLIC_RSA);
						personalKey.setKeyStr(new String(publicKey.encode()));
						return KeyRSAObjectFragment.newInstance(personalKey);
					} catch (CryptoUtilsException e1) {
						Toast.makeText(getApplicationContext(),
								R.string.error_key_decode, Toast.LENGTH_LONG)
								.show();
						e1.printStackTrace();
					} catch (DBException e2) {
						Toast.makeText(getApplicationContext(),
								R.string.error_key_decode, Toast.LENGTH_LONG)
								.show();
						e2.printStackTrace();
					}
				} catch (DBException e) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_decode, Toast.LENGTH_LONG)
							.show();
					e.printStackTrace();
				}
				return CurrentlyNotAvailableFragment.newInstance();
			case OWNER_PAGE:
				return CertificateOwnerInformationFragment
						.newInstance(certificatePosition);
			case CERTIFICATE_PAGE:
				return CertificateDecodedInformationFragment
						.newInstance(certificatePosition);
			case ISSUER_PAGE:
				return CertificateIssuerInformationFragment
						.newInstance(certificatePosition);
			default:
				return CertificateDecodedInformationFragment
						.newInstance(certificatePosition);
			}
		}

		@Override
		public int getCount() {
			return 4;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case PUBLIC_KEY_PAGE:
				return getResources().getString(
						R.string.detail_title_public_key);
			case OWNER_PAGE:
				return getResources().getString(R.string.detail_title_holder);
			case CERTIFICATE_PAGE:
				return getResources().getString(
						R.string.detail_title_certificate);
			case ISSUER_PAGE:
				return getResources().getString(R.string.detail_title_issuer);
			default:
				return getResources().getString(
						R.string.detail_title_certificate);
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

			// If the id in the current selected item is 0, it means that was
			// deleted, so it should be removed and the pager should be updated
			if (shouldUpdate) {
				Log.i(PKITrustNetworkActivity.TAG, " 2 DELETE: " + ids);
				return POSITION_NONE;
			}

			return POSITION_UNCHANGED;
		}

	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment representing an object in the collection. This collection will
	 * have always 2 pages, one for certificate X509 extensions, one for the
	 * application specific extensions
	 */
	public class CertificateExtensionsCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		/**
		 * Certificate position in the certificate view pager, to be used as
		 * reference when hide details is selected
		 */
		Integer certificatePosition;
		Boolean shouldUpdate;

		/**
		 * Certificate Details Page in the certificate details view pager, to be
		 * used as reference when hiding the extensions view
		 */
		Integer certificateDetailsPage;

		public static final int SPECIFIC_PAGE = 0;
		public static final int STANDARD_PAGE = 1;

		public CertificateExtensionsCollectionPagerAdapter(FragmentManager fm,
				Integer certificatePosition, Integer certificateDetailsPage) {
			super(fm);
			this.certificatePosition = certificatePosition;
			this.certificateDetailsPage = certificateDetailsPage;
		}

		/**
		 * @return the certificatePosition
		 */
		public Integer getCertificatePosition() {
			return certificatePosition;
		}

		/**
		 * @param certificatePosition
		 *            the certificatePosition to set
		 */
		public void setCertificatePosition(Integer certificatePosition) {
			this.certificatePosition = certificatePosition;
		}

		/**
		 * @return the certificateDetailsPage
		 */
		public Integer getCertificateDetailsPage() {
			return certificateDetailsPage;
		}

		/**
		 * @param shouldUpdate
		 *            the shouldUpdate to set
		 */
		public void setShouldUpdate(Boolean shouldUpdate) {
			this.shouldUpdate = shouldUpdate;
		}

		/**
		 * @param certificateDetailsPage
		 *            the certificateDetailsPage to set
		 */
		public void setCertificateDetailsPage(Integer certificateDetailsPage) {
			this.certificateDetailsPage = certificateDetailsPage;
		}

		@Override
		public Fragment getItem(int i) {
			shouldUpdate = Boolean.FALSE;
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM [" + i + "]");
			getSupportActionBar().setSubtitle(R.string.subtitle_cert_extension);
			switch (i) {
			case SPECIFIC_PAGE:
				return CertificateCustomExtensionsInformationFragment
						.newInstance(certificatePosition,
								certificateDetailsPage);
			case STANDARD_PAGE:
				return CertificateExtensionsInformationFragment.newInstance(
						certificatePosition, certificateDetailsPage);
			default:
				return CertificateExtensionsInformationFragment.newInstance(
						certificatePosition, certificateDetailsPage);
			}
		}

		@Override
		public int getCount() {
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case SPECIFIC_PAGE:
				return getResources().getString(
						R.string.detail_title_extension_specific);
			case STANDARD_PAGE:
				return getResources().getString(
						R.string.detail_title_extension_standar);
			default:
				return getResources().getString(
						R.string.detail_title_extension_standar);
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

			// If the id in the current selected item is 0, it means that was
			// deleted, so it should be removed and the pager should be updated
			if (shouldUpdate) {
				Log.i(PKITrustNetworkActivity.TAG, "3 DELETE: " + ids);
				return POSITION_NONE;
			}

			return POSITION_UNCHANGED;
		}

	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment representing an object in the collection. This collection will
	 * have only one page, for showing the map containing the certificate
	 * creation position
	 */
	public class CertificatePositionCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		/**
		 * Certificate position in the certificate view pager, to be used as
		 * reference when hide details is selected
		 */
		Integer certificatePosition;
		Boolean shouldUpdate;

		/**
		 * Certificate Details Page in the certificate details view pager, to be
		 * used as reference when hiding the extensions view
		 */
		Integer certificateDetailsPage;

		/**
		 * GPS Latitude coordinate to be shown in the map
		 */
		Float gpsPositionLat;

		/**
		 * GPS Longitude coordinate to be shown in the map
		 */
		Float gpsPositionLon;

		public CertificatePositionCollectionPagerAdapter(FragmentManager fm,
				Integer certificatePosition, Integer certificateDetailsPage,
				Float gpsPositionLat, Float gpsPositionLon) {
			super(fm);
			this.certificatePosition = certificatePosition;
			this.certificateDetailsPage = certificateDetailsPage;
			this.gpsPositionLat = gpsPositionLat;
			this.gpsPositionLon = gpsPositionLon;
		}

		/**
		 * @param shouldUpdate
		 *            the shouldUpdate to set
		 */
		public void setShouldUpdate(Boolean shouldUpdate) {
			this.shouldUpdate = shouldUpdate;
		}

		/**
		 * @return the certificatePosition
		 */
		public Integer getCertificatePosition() {
			return certificatePosition;
		}

		/**
		 * @param certificatePosition
		 *            the certificatePosition to set
		 */
		public void setCertificatePosition(Integer certificatePosition) {
			this.certificatePosition = certificatePosition;
		}

		/**
		 * @return the certificateDetailsPage
		 */
		public Integer getCertificateDetailsPage() {
			return certificateDetailsPage;
		}

		/**
		 * @param certificateDetailsPage
		 *            the certificateDetailsPage to set
		 */
		public void setCertificateDetailsPage(Integer certificateDetailsPage) {
			this.certificateDetailsPage = certificateDetailsPage;
		}

		/**
		 * @return the gpsPositionLat
		 */
		public Float getGpsPositionLat() {
			return gpsPositionLat;
		}

		/**
		 * @param gpsPositionLat
		 *            the gpsPositionLat to set
		 */
		public void setGpsPositionLat(Float gpsPositionLat) {
			this.gpsPositionLat = gpsPositionLat;
		}

		/**
		 * @return the gpsPositionLon
		 */
		public Float getGpsPositionLon() {
			return gpsPositionLon;
		}

		/**
		 * @param gpsPositionLon
		 *            the gpsPositionLon to set
		 */
		public void setGpsPositionLon(Float gpsPositionLon) {
			this.gpsPositionLon = gpsPositionLon;
		}

		@Override
		public Fragment getItem(int i) {
			shouldUpdate = Boolean.FALSE;
			getSupportActionBar().setSubtitle(R.string.subtitle_cert_extension);

			return CertificateCustomExtensionsPositionFragment.newInstance(
					certificatePosition, certificateDetailsPage,
					gpsPositionLat, gpsPositionLon);
		}

		@Override
		public int getCount() {
			return 1;
		}

		@Override
		public CharSequence getPageTitle(int position) {

			return getResources().getString(
					R.string.detail_title_extension_position);

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

			// If the id in the current selected item is 0, it means that was
			// deleted, so it should be removed and the pager should be updated
			if (shouldUpdate) {
				Log.i(PKITrustNetworkActivity.TAG, "4 DELETE: " + ids);
				return POSITION_NONE;
			}

			return POSITION_UNCHANGED;
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.actionbarsherlock.app.SherlockFragmentActivity#onCreateOptionsMenu
	 * (com.actionbarsherlock.view.Menu)
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// If trustedListOwnerId is 0, should display certificate options
		if (trustedListOwnerId == 0 && trustedCertificateId == 0) {
			// Place an action bar item for signing the certificate.
			/** Inflating the current activity's menu with res/menu/items.xml */
			getSupportMenuInflater().inflate(R.menu.cert_menu, menu);

			/**
			 * Getting the action provider associated with the menu item whose
			 * id is share
			 */
			mShareActionProvider = (ShareActionProvider) menu.findItem(
					R.id.menu_cert_share).getActionProvider();

		} else {
			// otherwise, show trusted certificate options
			// if trustedCertificateId is 0, means that the view will only show
			// the information
			if (trustedCertificateId == 0) {
				// Place an action bar item for delete the certificate from the
				// trusted list.
				menu.add(0, MENU_OPTION_TRUST_DELETE, 0, R.string.menu_delete)
						.setIcon(R.drawable.ic_action_trust_cert_delete)
						.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

				// Place an action bar item for modifying the certificates trust
				// in
				// the trusted list.
				menu.add(0, MENU_OPTION_TRUST_LEVEL, 1, R.string.menu_update)
						.setIcon(R.drawable.ic_action_trust_cert_level)
						.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

				// Place an action bar item for export the trusted certificate
				// in
				// trustcertificate list format.
				menu.add(0, MENU_OPTION_TRUST_EXPORT, 2, R.string.menu_export)
						.setIcon(R.drawable.ic_action_trust_cert_export)
						.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

				// Place an action bar item for send the trusted certificate in
				// trustcertificate list format.
				menu.add(0, MENU_OPTION_TRUST_SEND, 3, R.string.menu_send)
						.setIcon(R.drawable.ic_action_trust_cert_send)
						.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
			} else {
				// If is different from 0, means that the user could edit the
				// certificate trust level and save it
				// Place an action bar item for send the trusted certificate in
				// trustcertificate list format.
				if (!updateTrustCertificate) {
					// If the trust certificate will be added
					menu.add(0, MENU_OPTION_TRUST_ADD, 3, R.string.menu_add)
							.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
				} else {
					// If the trust certificate will be updated
					menu.add(0, MENU_OPTION_TRUST_UPDATE, 3,
							R.string.menu_update).setShowAsAction(
							MenuItem.SHOW_AS_ACTION_IF_ROOM);
				}
			}
		}

		return super.onCreateOptionsMenu(menu);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.KeyObjectFragment.
	 * OnClickECDetailsLis tener
	 * #onClickMoreDetails(cinvestav.android.pki.db.dao .PersonalKeyDAO)
	 */
	@Override
	public void onMoreDetails(CertificateDAO cert) {
		// Check if the task is not created or if the task is running
		if (decodeX509CertificateTask == null
				|| !decodeX509CertificateTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			decodeX509CertificateTask = new DecodeX509CertificateTask();
			decodeX509CertificateTask.execute(cert);
		} else {
			Toast.makeText(getApplicationContext(), R.string.msgWorking,
					Toast.LENGTH_SHORT).show();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateIssuerInformationFragment
	 * .OnClickCertificateIssuerListener#onSearchIssuerCertificate
	 * (java.lang.Integer)
	 */
	@Override
	public void onSearchIssuerCertificate(Integer certificatePosition) {

		CertificateDAO certificate;
		try {
			// Get certificate from data base
			certificate = certificateController.getById(ids
					.get(certificatePosition));

			// Fill certificate details - get CA certificate information
			certificateController.getCertificateDetails(certificate);

			// Get CA certificate
			CertificateDAO caCertificate = certificate.getCaCertificate();
			if (caCertificate != null) {
				// If the certificate is found open its details
				Intent intent = new Intent(getApplicationContext(),
						CertificateDetailsActivity.class);
				int ownerId = caCertificate.getOwner().getId();
				intent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID,
						ownerId);
				intent.putExtra(
						CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID,
						caCertificate.getId());
				startActivity(intent);
			} else {
				// If the certificate is null, show an error
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_search_issuer, Toast.LENGTH_LONG)
						.show();
			}
		} catch (DBException e) {
			Toast.makeText(getApplicationContext(),
					R.string.error_cert_search_issuer, Toast.LENGTH_LONG)
					.show();
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link X509Certificate} is loaded and decoded from a
	 * {@link CertificateDAO} object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class DecodeX509CertificateTask extends
			AsyncTask<CertificateDAO, Void, X509Certificate> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected X509Certificate doInBackground(CertificateDAO... params) {

			try {
				return x509Utils.decode(params[0].getCertificateStr()
						.getBytes());
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(X509Certificate certificate) {
			if (certificate != null) {

				setSelectedCertificate(certificate);
				// Create an adapter that when requested, will return a fragment
				// representing an object in the collection.
				// ViewPager and its adapters use support library fragments, so
				// we
				// must use getSupportFragmentManager.
				certificateCollectionPagerAdapter = new CertificateDecodedCollectionPagerAdapter(
						getSupportFragmentManager(),
						mViewPager.getCurrentItem());

				// Set up the ViewPager, attaching the adapter.
				mViewPager.setAdapter(certificateCollectionPagerAdapter);
				mViewPager
						.setCurrentItem(CertificateDecodedCollectionPagerAdapter.CERTIFICATE_PAGE);
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_decode, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);

		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateDecodedInformationFragment
	 * .OnClickCertificateDecodeListener#onSeeExtention(java.lang.Integer)
	 */
	@Override
	public void onSeeExtention(Integer certificatePosition) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		certificateCollectionPagerAdapter = new CertificateExtensionsCollectionPagerAdapter(
				getSupportFragmentManager(), certificatePosition,
				(Integer) mViewPager.getCurrentItem());

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager
				.setCurrentItem(CertificateExtensionsCollectionPagerAdapter.STANDARD_PAGE);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateDecodedInformationFragment
	 * .OnClickCertificateDecodeListener#onHideDetails(java.lang.Integer)
	 */
	@Override
	public void onHideDetails(Integer certificatePosition) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager.setCurrentItem(certificatePosition);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateCustomExtensionsPositionFragment
	 * .OnClickCertificateExtensionPositionListener#onHideMap(java.lang.Integer,
	 * java.lang.Integer)
	 */
	@Override
	public void onHideMap(Integer certificatePosition,
			Integer certificateDetailsPage) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		certificateCollectionPagerAdapter = new CertificateExtensionsCollectionPagerAdapter(
				getSupportFragmentManager(), certificatePosition,
				certificateDetailsPage);

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager
				.setCurrentItem(CertificateExtensionsCollectionPagerAdapter.SPECIFIC_PAGE);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateCustomExtensionsInformationFragment
	 * .OnClickCertificateCustomExtensionListener#onSeeMap(java.lang.Integer,
	 * java.lang.Integer, java.lang.Float, java.lang.Float)
	 */
	@Override
	public void onSeeMap(Integer certificatePosition,
			Integer certificateDetailsPage, Float gpsPositionLat,
			Float gpsPositionLon) {
		if (mapView == null) {
			/*
			 * View mMapViewContainer = LayoutInflater.from(this).inflate(
			 * R.layout.detail_certificate_fragment_position, null); mapView =
			 * (MapView) mMapViewContainer.findViewById(R.id.mapview);
			 */

			mapView = new MapView(this,
					"0u-HXCh9yfz7yEyaSqY2_z8xywEeCRrls-iUV3w");
			mapView.setClickable(true);
			mapView.setBuiltInZoomControls(true);
		}

		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		certificateCollectionPagerAdapter = new CertificatePositionCollectionPagerAdapter(
				getSupportFragmentManager(), certificatePosition,
				certificateDetailsPage, gpsPositionLat, gpsPositionLon);

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager.setCurrentItem(0);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.
	 * CertificateExtensionsInformationFragment
	 * .OnClickCertificateExtensionListener#onHideExtension(java.lang.Integer,
	 * java.lang.Integer)
	 */
	@Override
	public void onHideExtension(Integer certificatePosition,
			Integer certificateDetailsPage) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		certificateCollectionPagerAdapter = new CertificateDecodedCollectionPagerAdapter(
				getSupportFragmentManager(), certificatePosition);

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager.setCurrentItem(certificateDetailsPage);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.KeyRSAObjectFragment.
	 * OnClickRSADetailsListener #onHideRSADetails(cinvestav.android.pki.db.dao
	 * .PersonalKeyDAO)
	 */
	@Override
	public void onHideRSADetails(PersonalKeyDAO key) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		Integer certificatePosition = ((CertificateDecodedCollectionPagerAdapter) mViewPager
				.getAdapter()).getCertificatePosition();
		certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager.setCurrentItem(certificatePosition);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.KeyECObjectFragment.
	 * OnClickECDetailsListener #onHideECDetails(cinvestav.android.pki.db.dao
	 * .PersonalKeyDAO)
	 */
	@Override
	public void onHideECDetails(PersonalKeyDAO key) {
		certificateCollectionPagerAdapter = null;
		// Create an adapter that when requested, will return a fragment
		// representing an object in the collection.
		// ViewPager and its adapters use support library fragments, so we
		// must use getSupportFragmentManager.
		Integer certificatePosition = ((CertificateDecodedCollectionPagerAdapter) mViewPager
				.getAdapter()).getCertificatePosition();
		certificateCollectionPagerAdapter = new CertificateCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager.setAdapter(certificateCollectionPagerAdapter);
		mViewPager.setCurrentItem(certificatePosition);

	}

	/**
	 * Static inner class for creating a Fragment dialog that contains simply
	 * YES/No buttons, to be used for confirm some actions
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 03/09/2012
	 * @version 1.0
	 */
	public static class MyConfirmationDialogFrament extends
			SherlockDialogFragment {

		public static MyConfirmationDialogFrament newInstance(int title) {
			MyConfirmationDialogFrament frag = new MyConfirmationDialogFrament();
			Bundle args = new Bundle();
			args.putInt("title", title);
			frag.setArguments(args);
			return frag;
		}

		@Override
		public Dialog onCreateDialog(Bundle savedInstanceState) {
			int title = getArguments().getInt("title");

			return new AlertDialog.Builder(getActivity())
					.setIcon(R.drawable.ic_alert)
					.setTitle(title)
					.setPositiveButton(R.string.alert_dialog_ok,
							new DialogInterface.OnClickListener() {
								public void onClick(DialogInterface dialog,
										int whichButton) {
									((CertificateDetailsActivity) getActivity())
											.deleteTrustedCertificate();
								}
							})
					.setNegativeButton(R.string.alert_dialog_cancel,
							new DialogInterface.OnClickListener() {
								public void onClick(DialogInterface dialog,
										int whichButton) {

								}
							}).create();
		}
	}
}
