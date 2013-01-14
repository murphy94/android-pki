/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	In this Fragment activity the key Details will be shown as a collection, so that using swipe action
 *  the user could navigate in it
 */
package cinvestav.pki.android.trustednetwork.details;

import java.io.File;
import java.security.cert.Certificate;
import java.util.ArrayList;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment.OnPositiveButtonClickListener;
import cinvestav.pki.android.trustednetwork.common.MyPasswordPKCSDialogFragment;
import cinvestav.pki.android.trustednetwork.details.KeyObjectFragment.OnClickDetailsListener;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.share.ExportKeyActivity;
import cinvestav.pki.android.trustednetwork.update.UpdateKeyActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockDialogFragment;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;
import com.actionbarsherlock.widget.ShareActionProvider;

/**
 * In this Fragment activity the key Details will be shown as a collection, so
 * that using swipe action the user could navigate in it
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class KeyDetailsActivity extends SherlockFragmentActivity
		implements
		OnClickDetailsListener,
		cinvestav.pki.android.trustednetwork.details.KeyRSAObjectFragment.OnClickRSADetailsListener,
		cinvestav.pki.android.trustednetwork.details.KeyECObjectFragment.OnClickECDetailsListener {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	KeyCollectionPagerAdapter mCollectionPagerAdapter;
	ArrayList<Integer> ids;

	public static final String EXTRA_ID_ARRAY = "EXTRA_ID_ARRAY";
	public static final String EXTRA_CURRENT_ITEM = "EXTRA_CURRENT_ITEM";

	static PersonalKeyController personalKeyController;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	ViewPager mViewPager;

	private ShareActionProvider mShareActionProvider;

	private String password;
	private String passwordPKCS;

	private String rsaPublicFileName = Environment
			.getExternalStorageDirectory() + "/RSAPublicKey.der";
	private String rsaPrivateFileName = Environment
			.getExternalStorageDirectory() + "/RSAPrivateKey.pem";
	private String ecPublicFileName = Environment.getExternalStorageDirectory()
			+ "/ECPublicKey.der";
	private String ecPrivateFileName = Environment
			.getExternalStorageDirectory() + "/ECPrivateKey.pem";
	private String rsaPKCSFileName = Environment.getExternalStorageDirectory()
			+ "/RSAPKCS12Key.p12";
	private String ecPKCSFileName = Environment.getExternalStorageDirectory()
			+ "/ECPKCS12Key.p12";

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(
					getApplicationContext());

		}

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		int[] aux = getIntent().getIntArrayExtra(EXTRA_ID_ARRAY);
		ids = new ArrayList<Integer>(aux.length);
		for (int i = 0; i < aux.length; i++) {
			ids.add(aux[i]);
		}

		int currentItem = getIntent().getIntExtra(EXTRA_CURRENT_ITEM, 0);
		setContentView(R.layout.detail_collection);
		setSupportProgressBarIndeterminateVisibility(false);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new KeyCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_keys_collection);

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);
		mViewPager.setCurrentItem(currentItem);

		deleteExistingKeys();

	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		Intent upIntent;
		switch (item.getItemId()) {
		case android.R.id.home:
			// This is called when the Home (Up) button is pressed in the action
			// bar.
			// Create a simple intent that starts the hierarchical parent
			// activity and
			// use NavUtils in the Support Package to ensure proper handling of
			// Up.
			upIntent = new Intent(this, PKITrustNetworkActivity.class);
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
			return true;
		case R.id.menu_key_delete:

			DialogFragment newFragment = MyConfirmationDialogFrament
					.newInstance(R.string.alert_dialog_key_delete_title);
			newFragment.show(getSupportFragmentManager(), "dialog");

			break;
		case R.id.menu_key_export:
			export();
			break;

		case R.id.menu_key_share:
			share();
			break;
		case R.id.menu_key_update:
			update();
			break;
		}
		return super.onOptionsItemSelected(item);
	}

	/**
	 * Shares the selected key using Android Share menu, but first check if the
	 * key could be shared asking the password for private keys
	 */
	public void share() {
		try {
			PersonalKeyDAO key = personalKeyController.getById(ids
					.get(mViewPager.getCurrentItem()));

			Integer keyType = key.getKeyType();
			// If its a public key, password is not required for any operation
			if (keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
				doShareRSAPublicKey(key);
				return;
			}
			if (keyType.equals(PersonalKeyDAO.PUBLIC_EC)) {
				doShareECPublicKey(key);
				return;
			}

			// If the code reaches this point, the key is a private or PKCS key
			// Check the key type
			if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {

				// Remove the file if it exist, to prevent the key be sent if
				// the user press cancel or insert the wrong password
				File f = new File(rsaPrivateFileName);
				if (f.exists()) {
					f.delete();
				}

				/** Setting a share intent */
				mShareActionProvider
						.setShareIntent(getDefaultShareIntent(rsaPrivateFileName));

				// If is a RSAPrivateKey ask for the password
				DialogFragment newFragment = MyPasswordDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerShareImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
				// Remove the file if it exist, to prevent the key be sent if
				// the user press cancel or insert the wrong password
				File f = new File(rsaPKCSFileName);
				if (f.exists()) {
					f.delete();
				}

				/** Setting a share intent */
				mShareActionProvider
						.setShareIntent(getDefaultShareIntent(rsaPKCSFileName));
				// If is a PKCS_RSA file, ask for the password
				DialogFragment newFragment = MyPasswordPKCSDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerShareImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {

				// Remove the file if it exist, to prevent the key be sent if
				// the user press cancel or insert the wrong password

				File f = new File(ecPrivateFileName);
				if (f.exists()) {
					f.delete();
				}
				/** Setting a share intent */
				mShareActionProvider
						.setShareIntent(getDefaultShareIntent(ecPrivateFileName));
				// If is a ECPrivateKey ask for the password
				DialogFragment newFragment = MyPasswordDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerShareImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {

				// Remove the file if it exist, to prevent the key be sent if
				// the user press cancel or insert the wrong password

				File f = new File(ecPKCSFileName);
				if (f.exists()) {
					f.delete();
				}

				// If is a PKCS_RC file, ask for the password
				/** Setting a share intent */
				mShareActionProvider
						.setShareIntent(getDefaultShareIntent(ecPKCSFileName));
				DialogFragment newFragment = MyPasswordPKCSDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerShareImp());
				newFragment.show(getSupportFragmentManager(), "password");
			}
		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_share_key, Toast.LENGTH_LONG)
					.show();
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
		}
	}

	/**
	 * Check if the files exist in the sd card and delete them
	 */
	private void deleteExistingKeys() {
		File f = new File(rsaPublicFileName);
		if (f.exists()) {
			f.delete();
		}

		f = new File(ecPublicFileName);
		if (f.exists()) {
			f.delete();
		}

		f = new File(rsaPrivateFileName);
		if (f.exists()) {
			f.delete();
		}

		f = new File(ecPrivateFileName);
		if (f.exists()) {
			f.delete();
		}

		f = new File(rsaPKCSFileName);
		if (f.exists()) {
			f.delete();
		}

		f = new File(ecPKCSFileName);
		if (f.exists()) {
			f.delete();
		}
	}

	/**
	 * Perform the share operation of a {@link RSAPublicKey}
	 * 
	 * @param key
	 *            {@link PersonalKeyDAO} object containing an
	 *            {@link ECPublicKey} object
	 */
	public void doShareRSAPublicKey(PersonalKeyDAO key) {

		File f = new File(rsaPublicFileName);
		if (f.exists()) {
			f.delete();
		}
		try {
			/** Setting a share intent */
			mShareActionProvider
					.setShareIntent(getDefaultShareIntent(rsaPublicFileName));

			RSAPublicKey.decode(key.getKeyStr().getBytes()).saveDER(
					rsaPublicFileName);

		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Perform the share operation of a {@link ECPublicKey}
	 * 
	 * @param key
	 *            {@link PersonalKeyDAO} object containing an
	 *            {@link ECPublicKey} object
	 */
	public void doShareECPublicKey(PersonalKeyDAO key) {
		File f = new File(ecPublicFileName);
		if (f.exists()) {
			f.delete();
		}
		try {
			ECPublicKey.decode(key.getKeyStr().getBytes()).saveDER(
					ecPublicFileName);

			/** Setting a share intent */
			mShareActionProvider
					.setShareIntent(getDefaultShareIntent(ecPublicFileName));

		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Perform the share operation over a {@link RSAPrivateKey} that was decoded
	 * in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded RSA private key
	 */
	public void doShare(RSAPrivateKey privateKey) {

		try {
			privateKey.savePKCS8PEM(rsaPrivateFileName,
					CryptoUtils.AES_256_CBC, password);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Perform the share operation over a {@link ECPrivateKey} that was decoded
	 * in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded EC private key
	 */
	public void doShare(ECPrivateKey privateKey) {

		try {
			privateKey.savePKCS8PEM(ecPrivateFileName, CryptoUtils.AES_256_CBC,
					password);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Perform the share operation over a {@link RSAKeyPair} that was decoded in
	 * {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void doShare(RSAKeyPair keyPair, Certificate[] chain) {

		try {
			keyPair.savePKCS12(rsaPKCSFileName, passwordPKCS, password,
					(Certificate[]) chain);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
		}
	}

	/**
	 * Perform the share operation over a {@link ECKeyPair} that was decoded in
	 * {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void doShare(ECKeyPair keyPair, Certificate[] chain) {
		try {
			keyPair.savePKCS12(ecPKCSFileName, passwordPKCS, password,
					(Certificate[]) chain);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			Toast.makeText(getApplicationContext(), R.string.error_key_share,
					Toast.LENGTH_LONG).show();
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
		// share();
		// String filePath = getFilesDir().getAbsolutePath() +
		// "/RSAPrivateKey.pem";
		File f = new File(filePath);
		Intent shareIntent = new Intent();
		shareIntent.setAction(Intent.ACTION_SEND);
		shareIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(f));
		shareIntent.setType("text/plain");
		return shareIntent;
	}

	public void canDelete() {

		try {
			PersonalKeyDAO key = personalKeyController.getById(ids
					.get(mViewPager.getCurrentItem()));

			Integer keyType = key.getKeyType();
			// If its a public key, password is not required for any operation
			if (keyType.equals(PersonalKeyDAO.PUBLIC_RSA)
					|| keyType.equals(PersonalKeyDAO.PUBLIC_EC)) {
				doDelete(key);
				return;
			}

			// If the code reaches this point, the key is a private or PKCS key
			// Check the key type
			if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
				// If is a RSAPrivateKey ask for the password

				DialogFragment newFragment = MyPasswordDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerDeleteImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
				// If is a PKCS_RSA file, ask for the password
				DialogFragment newFragment = MyPasswordPKCSDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerDeleteImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
				// If is a ECPrivateKey ask for the password
				DialogFragment newFragment = MyPasswordDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerDeleteImp());
				newFragment.show(getSupportFragmentManager(), "password");
			} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
				// If is a PKCS_RC file, ask for the password
				DialogFragment newFragment = MyPasswordPKCSDialogFragment
						.newInstance(
								R.string.alert_dialog_key_open_private_title,
								key,
								new OnPositiveButtonClickListenerDeleteImp());
				newFragment.show(getSupportFragmentManager(), "password");
			}

			// onClickMoreDetails(key, MENU_OPTION_DELETE);

		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_delete_key,
					Toast.LENGTH_LONG).show();
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
		}
	}

	/**
	 * Opens the update activity for the selected key
	 */
	public void update() {
		Intent upIntent = new Intent(this, UpdateKeyActivity.class);
		int[] idArray = new int[ids.size()];
		for (int i = 0; i < ids.size(); i++) {
			idArray[i] = ids.get(i);
		}
		upIntent.putExtra(EXTRA_ID_ARRAY, idArray);
		upIntent.putExtra(EXTRA_CURRENT_ITEM, mViewPager.getCurrentItem());
		startActivity(upIntent);
	}

	/**
	 * Opens the export activity for the selected key
	 */
	public void export() {
		Intent upIntent = new Intent(this, ExportKeyActivity.class);
		int[] idArray = new int[ids.size()];
		for (int i = 0; i < ids.size(); i++) {
			idArray[i] = ids.get(i);
		}
		upIntent.putExtra(EXTRA_ID_ARRAY, idArray);
		upIntent.putExtra(EXTRA_CURRENT_ITEM, mViewPager.getCurrentItem());
		startActivity(upIntent);
	}

	/**
	 * Deletes the current selected item from the data base and the view, this
	 * function is invoked from {@link MyConfirmationDialogFragment}
	 */
	public void doDelete(PersonalKeyDAO key) {

		try {

			personalKeyController.delete(key);
			Toast.makeText(this, R.string.db_delete_key_ok, Toast.LENGTH_LONG)
					.show();
			// ids.set(mViewPager.getCurrentItem(), 0);
			ids.remove(mViewPager.getCurrentItem());
			if (ids.size() <= 0) {
				Intent upIntent = new Intent(this,
						PKITrustNetworkActivity.class);
				if (NavUtils.shouldUpRecreateTask(this, upIntent)) {
					// This activity is not part of the application's task,
					// so
					// create a new task
					// with a synthesized back stack.
					TaskStackBuilder.create(this)
					// If there are ancestor activities, they should be
					// added
					// here.
							.addNextIntent(upIntent).startActivities();
					finish();
				} else {
					// This activity is part of the application's task, so
					// simply
					// navigate up to the hierarchical parent activity.
					NavUtils.navigateUpTo(this, upIntent);
				}
			}
			mCollectionPagerAdapter.setShouldUpdate(Boolean.TRUE);
			Log.i(PKITrustNetworkActivity.TAG, "DELETE: " + ids);
			mCollectionPagerAdapter.notifyDataSetChanged();

		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_delete_key,
					Toast.LENGTH_LONG).show();
			e.printStackTrace();
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
		}
	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment representing an object in the collection.
	 */
	public class KeyCollectionPagerAdapter extends FragmentStatePagerAdapter {

		Fragment keyFragment;
		int currentPos;
		Boolean shouldUpdate;

		// private final FragmentManager mFragmentManager;

		public KeyCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			currentPos = 0;
			shouldUpdate = Boolean.FALSE;
			// mFragmentManager = fm;
		}

		/**
		 * @return the certificateFragment
		 */
		public Fragment getKeyFragment() {
			return keyFragment;
		}

		/**
		 * @param certificateFragment
		 *            the certificateFragment to set
		 */
		public void setKeyFragment(Fragment keyFragment) {
			this.keyFragment = keyFragment;
		}

		/**
		 * @return the currentPos
		 */
		public int getCurrentPos() {
			return currentPos;
		}

		/**
		 * @param currentPos
		 *            the currentPos to set
		 */
		public void setCurrentPos(int currentPos) {
			this.currentPos = currentPos;
		}

		/**
		 * @return the shouldUpdate
		 */
		public Boolean getShouldUpdate() {
			return shouldUpdate;
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
			// If the certificateFragment is an instance of KeyRSAObjectFragment
			// or
			// KeyECObjectFrame and the currentPos is the same
			// as the item position, do not create a new instance, just return
			// the existing one because
			// it was created when the SeeMoreDetails button was pressed
			if ((keyFragment instanceof KeyRSAObjectFragment || keyFragment instanceof KeyECObjectFragment)
					&& currentPos == i) {
				getSupportActionBar()
						.setSubtitle(R.string.subtitle_keys_detail);
				return keyFragment;
			}

			getSupportActionBar()
					.setSubtitle(R.string.subtitle_keys_collection);
			// Create a new instance for the fragment, pass the key id and the
			// controllers
			keyFragment = KeyObjectFragment.newInstance(ids.get(i));
			return keyFragment;
		}

		@Override
		public int getCount() {
			// Get the count of personal Keys
			return ids.size();
		}

		@Override
		public CharSequence getPageTitle(int position) {
			return getResources().getString(R.string.detail_title_key) + " "
					+ (position + 1);
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

			// Check if the adapter is called from the old fragment and if this
			// one has the flag getMoreDetails enabled, return POSITION_NONE so
			// the fragment is destroyed and reloaded
			if (object instanceof KeyObjectFragment) {
				KeyObjectFragment aux = (KeyObjectFragment) object;
				if (aux.getMoreDetails()) {
					return POSITION_NONE;
				}
			}
			if (object instanceof KeyRSAObjectFragment)
				return POSITION_NONE;
			if (object instanceof KeyECObjectFragment)
				return POSITION_NONE;
			// If the id in the current selected item is 0, it means that was
			// deleted, so it should be removed and the pager should be updated
			if (shouldUpdate) {
				return POSITION_NONE;
			}

			return POSITION_UNCHANGED;
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.KeyObjectFragment.
	 * OnClickECDetailsListener #onClickMoreDetails(cinvestav.android.pki.db.dao
	 * .PersonalKeyDAO)
	 */
	@Override
	public void onMoreDetails(PersonalKeyDAO key) {

		// Set the currentPos to the current Item in the view pager
		mCollectionPagerAdapter.currentPos = mViewPager.getCurrentItem();
		Integer keyType = key.getKeyType();
		// If its a public key, password is not required for any operation
		if (keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyRSAObjectFragment for the
			// adapter fragment

			mCollectionPagerAdapter.keyFragment = KeyRSAObjectFragment
					.newInstance(key);
			mCollectionPagerAdapter.notifyDataSetChanged();
			return;

		} else if (keyType.equals(PersonalKeyDAO.PUBLIC_EC)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyECObjectFragment for the
			// adapter fragment
			mCollectionPagerAdapter.keyFragment = KeyECObjectFragment
					.newInstance(key);
			mCollectionPagerAdapter.notifyDataSetChanged();
			return;
		}

		// If the code reaches this point, the key is a private or PKCS key
		// Check the key type
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			// If is a RSAPrivateKey ask for the password

			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, key,
					new OnPositiveButtonClickListenerSeeDetailsImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// If is a PKCS_RSA file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(R.string.alert_dialog_key_open_private_title,
							key,
							new OnPositiveButtonClickListenerSeeDetailsImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			// If is a ECPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, key,
					new OnPositiveButtonClickListenerSeeDetailsImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// If is a PKCS_RC file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(R.string.alert_dialog_key_open_private_title,
							key,
							new OnPositiveButtonClickListenerSeeDetailsImp());
			newFragment.show(getSupportFragmentManager(), "password");
		}

	}

	/**
	 * Show the details of a key after the key password is inserted, is invoked
	 * from {@link MyPasswordDialogFrament}
	 */
	public void onShowDetailWithPassword(PersonalKeyDAO key, String keyPassword) {
		if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_RSA)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyRSAObjectFragment for the adapter
			// fragment
			mCollectionPagerAdapter.keyFragment = KeyRSAObjectFragment
					.newInstance(key, keyPassword);
			mCollectionPagerAdapter.notifyDataSetChanged();
		} else if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyRSAObjectFragment for the adapter
			// fragment
			mCollectionPagerAdapter.keyFragment = KeyECObjectFragment
					.newInstance(key, keyPassword);
			mCollectionPagerAdapter.notifyDataSetChanged();
		}
	}

	/**
	 * Show the details of a key after the key and pkcs file passwords are
	 * inserted, is invoked from {@link MyPasswordPKCSDialogFrament}
	 */
	public void onShowDetailWithPassword(PersonalKeyDAO key,
			String keyPassword, String pkcsPassword) {
		if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_RSA)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyRSAObjectFragment for the adapter
			// fragment
			mCollectionPagerAdapter.keyFragment = KeyRSAObjectFragment
					.newInstance(key, keyPassword, pkcsPassword);
			mCollectionPagerAdapter.notifyDataSetChanged();
		} else if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
			setSupportProgressBarIndeterminateVisibility(true);
			// Create a new instance of KeyRSAObjectFragment for the adapter
			// fragment
			mCollectionPagerAdapter.keyFragment = KeyECObjectFragment
					.newInstance(key, keyPassword, pkcsPassword);
			mCollectionPagerAdapter.notifyDataSetChanged();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.pki.android.trustednetwork.details.KeyRSAObjectFragment.
	 * OnClickECDetailsListener
	 * #onHideDetails(cinvestav.android.pki.db.dao.PersonalKeyDAO)
	 */
	@Override
	public void onHideRSADetails(PersonalKeyDAO key) {
		mCollectionPagerAdapter.keyFragment = new KeyObjectFragment();
		mCollectionPagerAdapter.notifyDataSetChanged();

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
		mCollectionPagerAdapter.keyFragment = new KeyObjectFragment();
		mCollectionPagerAdapter.notifyDataSetChanged();

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

		/** Inflating the current activity's menu with res/menu/items.xml */
		getSupportMenuInflater().inflate(R.menu.key_menu, menu);

		/**
		 * Getting the action provider associated with the menu item whose id is
		 * share
		 */
		mShareActionProvider = (ShareActionProvider) menu.findItem(
				R.id.menu_key_share).getActionProvider();

		return super.onCreateOptionsMenu(menu);
	}

	/**
	 * Implements the OnPositiveButtonClickListener for SeeDetails operation,
	 * after the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerSeeDetailsImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			onShowDetailWithPassword(key, passwordKey);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			onShowDetailWithPassword(key, passwordKey, passwordPKCS);
		}

	}

	/**
	 * Implements the OnPositiveButtonClickListener for Delete operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerDeleteImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// If the operation is DELETE, the key should be decoded,
			// // if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
					// If the key is a private EC key
					ECPrivateKey
							.decode(key.getKeyStr().getBytes(), passwordKey);
				} else {
					// If the key is a private RSA key
					RSAPrivateKey.decode(key.getKeyStr().getBytes(),
							passwordKey);
				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return the
				// previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}

			// If the key was decoded correctly, delete the key
			doDelete(key);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// If the operation is DELETE, the key should be decoded,
			// if no
			// exception is thrown, it means that the inserted password is OK,
			// so the operation process should continue, if the password is
			// wrong
			// cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
					// If the key is a PKCS EC key

					ECKeyPair.decodePKCS12(key.getKeyStr().getBytes(),
							passwordPKCS, passwordKey);

				} else {
					// If the key is a PKCS RSA key
					RSAKeyPair.decodePKCS12(key.getKeyStr().getBytes(),
							passwordPKCS, passwordKey);

				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return
				// the previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}

			doDelete(key);

		}
	}

	/**
	 * Implements the OnPositiveButtonClickListener for Share operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerShareImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// If the operation is DELETE, the key should be decoded,
			// // if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
					// If the key is a private EC key
					ECPrivateKey privKey = ECPrivateKey.decode(key.getKeyStr()
							.getBytes(), passwordKey);

					// Share the decoded key
					password = passwordKey;
					doShare(privKey);
				} else {
					// If the key is a private RSA key
					RSAPrivateKey privKey = RSAPrivateKey.decode(key
							.getKeyStr().getBytes(), passwordKey);

					// Share the decoded key
					password = passwordKey;
					doShare(privKey);

				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return the
				// previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// If the operation is DELETE, the key should be decoded,
			// if no
			// exception is thrown, it means that the inserted password is OK,
			// so the operation process should continue, if the password is
			// wrong
			// cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
					// If the key is a PKCS EC key

					ECKeyPair.decodePKCS12(key.getKeyStr().getBytes(),
							passwordPKCS, passwordKey);

					Object[] decodedECKeyPair = ECKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					// Opens a dialog for sharing the key
					password = passwordKey;
					KeyDetailsActivity.this.passwordPKCS = passwordPKCS;
					doShare((ECKeyPair) decodedECKeyPair[0],
							(Certificate[]) decodedECKeyPair[1]);

				} else {
					// If the key is a PKCS RSA key
					Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					// Opens a dialog for sharing the key
					password = passwordKey;
					KeyDetailsActivity.this.passwordPKCS = passwordPKCS;
					doShare((RSAKeyPair) decodedRSAKeyPair[0],
							(Certificate[]) decodedRSAKeyPair[1]);

				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return
				// the previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}
		}
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
									((KeyDetailsActivity) getActivity())
											.canDelete();
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
