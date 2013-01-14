/**
 *  Created on  : 21/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, in this fragment a map view is
 * shown with the GPS position decoded from the certificate custom extensions
 * information
 * 
 */
package cinvestav.pki.android.trustednetwork.details;

import java.util.ArrayList;
import java.util.List;

import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;
import com.google.android.maps.GeoPoint;
import com.google.android.maps.ItemizedOverlay;
import com.google.android.maps.MapController;
import com.google.android.maps.MapView;
import com.google.android.maps.Overlay;
import com.google.android.maps.OverlayItem;

/**
 * A fragment representing a section of the app, in this fragment a map view is
 * shown with the GPS position decoded from the certificate custom extensions
 * information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 21/09/2012
 * @version 1.0
 */
public class CertificateCustomExtensionsPositionFragment extends
		SherlockFragment {

	/**
	 * Certificate position in the certificate view pager, to be used as
	 * reference when hide details is selected
	 */
	Integer certificatePosition;

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

	private static final String CERTIFICATE_POSITION = "CERTIFICATE_POSITION";
	private static final String CERTIFICATE_DETAIL_PAGE = "CERTIFICATE_DETAIL_PAGE";
	private static final String GPS_POSITION_LAT = "GPS_POSITION_LAT";
	private static final String GPS_POSITION_LON = "GPS_POSITION_LON";

	private java.text.DateFormat df;

	public CertificateCustomExtensionsPositionFragment() {
		super();
		certificatePosition = 0;
		certificateDetailsPage = 0;
		gpsPositionLat = 0.0f;
		gpsPositionLon = 0.0f;
	}

	public static CertificateCustomExtensionsPositionFragment newInstance(
			Integer certificatePosition, Integer certificateDetailsPage,
			Float gpsPositionLat, Float gpsPositionLon) {
		CertificateCustomExtensionsPositionFragment f = new CertificateCustomExtensionsPositionFragment();
		f.setCertificatePosition(certificatePosition);
		f.setCertificateDetailsPage(certificateDetailsPage);
		f.setGpsPositionLat(gpsPositionLat);
		f.setGpsPositionLon(gpsPositionLon);
		return f;
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
	public Float getGpsPositionX() {
		return gpsPositionLat;
	}

	/**
	 * @param gpsPositionLat
	 *            the gpsPositionLat to set
	 */
	public void setGpsPositionLat(Float gpsPositionX) {
		this.gpsPositionLat = gpsPositionX;
	}

	/**
	 * @return the gpsPositionLon
	 */
	public Float getGpsPositionY() {
		return gpsPositionLon;
	}

	/**
	 * @param gpsPositionLon
	 *            the gpsPositionLon to set
	 */
	public void setGpsPositionLon(Float gpsPositionY) {
		this.gpsPositionLon = gpsPositionY;
	}

	/**
	 * @return the df
	 */
	public java.text.DateFormat getDf() {
		return df;
	}

	/**
	 * @param df
	 *            the df to set
	 */
	public void setDf(java.text.DateFormat df) {
		this.df = df;
	}

	@Override
	public void onCreate(Bundle arg0) {
		super.onCreate(arg0);
		setRetainInstance(true);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater
				.inflate(R.layout.detail_certificate_fragment_position,
						container, false);

		final RelativeLayout mapLayout = (RelativeLayout) rootView
				.findViewById(R.id.layoutMap);

		TextView lblImgDetails = ((TextView) rootView
				.findViewById(R.id.lblImgHideDetails));

		MapView mapView = ((CertificateDetailsActivity) getActivity())
				.getMapView();
		if (null != mapView) {

			if (savedInstanceState != null) {
				certificatePosition = savedInstanceState
						.getInt(CERTIFICATE_POSITION);
				certificateDetailsPage = savedInstanceState
						.getInt(CERTIFICATE_DETAIL_PAGE);
				gpsPositionLat = savedInstanceState.getFloat(GPS_POSITION_LAT);
				gpsPositionLon = savedInstanceState.getFloat(GPS_POSITION_LON);
			}

			MapController mapController = mapView.getController();
			// GeoPoint coordinates are specified in microdegrees (degrees *
			// 1e6).
			GeoPoint point = new GeoPoint((int) (gpsPositionLat * 1.0e6),
					(int) (gpsPositionLon * 1.0e6));

			mapController.animateTo(point);
			mapController.setZoom(16);
			OverlayItem overlayitem = new OverlayItem(point,
					"Creation Position", "Certificate GPS Position");

			List<Overlay> mapOverlays = mapView.getOverlays();
			Drawable drawable = this.getResources().getDrawable(
					R.drawable.marker);
			MapItemOverlay itemizedoverlay = new MapItemOverlay(drawable);

			itemizedoverlay.addOverlay(overlayitem);
			mapOverlays.add(itemizedoverlay);

			mapLayout.addView(mapView, 1);

		}

		lblImgDetails.bringToFront();

		lblImgDetails.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				mapLayout
						.removeView(((CertificateDetailsActivity) getActivity())
								.getMapView());
				((OnClickCertificateExtensionPositionListener) getActivity())
						.onHideMap(certificatePosition, certificateDetailsPage);
			}
		});

		return rootView;
	}

	/**
	 * Interface that handles the click on SeeMoreDetails button for
	 * {@link CertificateExtensionsInformationFragment}, this should be
	 * implemented by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickCertificateExtensionPositionListener {

		/**
		 * Hide the certificate map
		 * 
		 * @param certificatePosition
		 *            Certificate position in the certificate view pager as
		 *            reference for return to the correct certificate
		 * @param certificateDetailsPage
		 *            Certificate Details Page position, in the certificate
		 *            details view pager, to be used as reference when hiding
		 *            the extensions view
		 */
		void onHideMap(Integer certificatePosition,
				Integer certificateDetailsPage);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.Fragment#onSaveInstanceState(android.os.Bundle)
	 */
	@Override
	public void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);
		outState.putInt(CERTIFICATE_POSITION, certificatePosition);
		outState.putInt(CERTIFICATE_DETAIL_PAGE, certificateDetailsPage);

		outState.putFloat(GPS_POSITION_LAT, gpsPositionLat);
		outState.putFloat(GPS_POSITION_LON, gpsPositionLon);
	}

	public class MapItemOverlay extends ItemizedOverlay<OverlayItem> {

		private ArrayList<OverlayItem> mOverlays = new ArrayList<OverlayItem>();

		// Context mContext;

		/**
		 * @param defaultMarker
		 */
		public MapItemOverlay(Drawable defaultMarker) {
			super(boundCenterBottom(defaultMarker));
		}

		/*
		 * public MapItemOverlay(Drawable defaultMarker, Context context) {
		 * super(boundCenterBottom(defaultMarker)); mContext = context; }
		 */

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.google.android.maps.ItemizedOverlay#createItem(int)
		 */
		@Override
		protected OverlayItem createItem(int i) {
			return mOverlays.get(i);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see com.google.android.maps.ItemizedOverlay#size()
		 */
		@Override
		public int size() {
			return mOverlays.size();
		}

		/**
		 * Add the overlay to the overlay List
		 * 
		 * @param overlay
		 */
		public void addOverlay(OverlayItem overlay) {
			mOverlays.add(overlay);
			populate();
		}

		/*
		 * @Override protected boolean onTap(int index) { OverlayItem item =
		 * mOverlays.get(index); AlertDialog.Builder dialog = new
		 * AlertDialog.Builder(mContext); dialog.setTitle(item.getTitle());
		 * dialog.setMessage(item.getSnippet()); dialog.show(); return true; }
		 */

	}
}
