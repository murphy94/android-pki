/**
 *  Created on  : 24/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for a list of signers of a certificate, this
 * list shows:
 * <ul>
 * <li>Owner name
 * <li>Issuer name
 * <li>DB status
 * <li>DB status update
 * <li>Serial number
 * <li>Trust level
 * </ul>
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

/**
 * Creates a custom list adapter for a list of signers of a certificate, this
 * list shows:
 * <ul>
 * <li>Owner name
 * <li>Issuer name
 * <li>DB status
 * <li>DB status update
 * <li>Serial number
 * <li>Trust level
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/08/2012
 * @version 1.0
 */
public class CertificateSignerListAdapter extends BaseAdapter {

	private Context context;
	private List<TrustedCertificateDAO> data;
	private static java.text.DateFormat df;

	/**
	 * Default constructor, for construct a certificate list adapter
	 * 
	 * @param context
	 *            Application context
	 * @param data
	 *            List of certificate to be shown in the list adapter
	 * @param certificateCount
	 *            Array that contains the owned certificate count for each
	 *            certificate in the list
	 */
	public CertificateSignerListAdapter(Context context,
			List<TrustedCertificateDAO> data) {
		this.context = context;
		this.data = data;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getCount()
	 */
	@Override
	public int getCount() {
		return data.size();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getItem(int)
	 */
	@Override
	public Object getItem(int position) {
		return data.get(position);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getItemId(int)
	 */
	@Override
	public long getItemId(int position) {
		return data.get(position).getId();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getView(int, android.view.View,
	 * android.view.ViewGroup)
	 */
	@Override
	public View getView(final int position, View convertView, ViewGroup parent) {
		final ViewCertificate holder;
		View vi = convertView;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();

		/**
		 * txtCertificateHolderAlias txtCertificateSerialNumber
		 * txtCertificateStatus txtCertificateStatusUpdate
		 * txtCertificateIssuerAlias txtTrustLevel imgSeeDetails
		 */

		// If convertView is null, the view is been created, so we need to get
		// its elements and saved the into a holder so they can be preserved and
		// loaded more efficiently, because the method findbyid is called only
		// the first time
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_signer_cert_with_trust,
					null);

			holder = new ViewCertificate();

			// Holder Alias
			holder.holderAlias = (TextView) vi
					.findViewById(R.id.txtCertificateHolderAlias);

			// Serial Number
			holder.serialNumber = (TextView) vi
					.findViewById(R.id.txtCertificateSerialNumber);

			// Status (DB)
			holder.status = (TextView) vi
					.findViewById(R.id.txtCertificateStatus);

			// Status Last Update(DB)
			holder.statusUpdate = (TextView) vi
					.findViewById(R.id.txtCertificateStatusUpdate);
			// Issuer Alias
			holder.issuerAlias = (TextView) vi
					.findViewById(R.id.txtCertificateIssuerAlias);

			// Certificate trust level
			holder.txtTrustLevel = (TextView) vi
					.findViewById(R.id.txtTrustLevel);

			holder.seeDetailsImg = (ImageView) vi
					.findViewById(R.id.imgSeeDetails);
			holder.seeDetailsImg.setClickable(true);
			holder.seeDetailsImg.setOnClickListener(new View.OnClickListener() {

				@Override
				public void onClick(View v) {
					onClickSeeDetails(position);
				}
			});

			vi.setTag(holder);

			if (df == null) {
				df = DateFormat.getDateFormat(context);
			}
		} else {
			holder = (ViewCertificate) vi.getTag();
		}

		TrustedCertificateDAO trustedCertificate = new TrustedCertificateDAO();
		trustedCertificate = data.get(position);
		CertificateDAO cert = trustedCertificate.getTrustedCertificate();

		String holderName;
		String serialNumber;
		String status;
		String statusUpdate;
		String issuerAlias;
		// Check if the certificate has id = 0 - means that the certificate is
		// unknown
		if (cert.getId().equals(0)) {
			// Fill with unknown or not available information values
			holderName = context.getString(R.string.lblUnkwnown);
			serialNumber = context.getString(R.string.lblNotAvailable);
			status = context.getString(R.string.lblNotAvailable);
			statusUpdate = context.getString(R.string.lblNotAvailable);
			issuerAlias = context.getString(R.string.lblUnkwnown);
		} else {
			// Fill with certificate information
			holderName = cert.getOwner().getName();
			serialNumber = cert.getSerialNumber() + "";
			status = cert.getStatusStr(PKITrustNetworkActivity.LAN);
			statusUpdate = df.format(cert.getLastStatusUpdateDate());
			CertificateDAO caCert = cert.getCaCertificate();
			if (caCert != null && !caCert.getId().equals(0)) {
				issuerAlias = cert.getCaCertificate().getOwner().getName();
			} else {
				issuerAlias = context.getString(R.string.lblUnkwnown);
			}
		}

		// Setting all values in listview

		holder.holderAlias.setText(holderName);
		holder.serialNumber.setText(context
				.getString(R.string.lblCertificateSerialNumber)
				+ ": "
				+ serialNumber);
		holder.status.setText(status);
		holder.statusUpdate.setText("(" + statusUpdate + ")");
		holder.issuerAlias.setText(context
				.getString(R.string.lblCertificateCASubjectName)
				+ ": "
				+ issuerAlias);
		holder.txtTrustLevel.setText(context
				.getString(R.string.lblCertificateTrustLevel)
				+ ": "
				+ (trustedCertificate.getTrustLevel() / 10.0));

		return vi;

	}

	static class ViewCertificate {
		TextView holderAlias;
		TextView serialNumber;
		TextView status;
		TextView statusUpdate;
		TextView issuerAlias;
		TextView txtTrustLevel;
		ImageView seeDetailsImg;
	}

	protected void onClickSeeDetails(int position) {
		Intent intent = new Intent(context, CertificateDetailsActivity.class);
		int ownerId = data.get(position).getTrustedCertificate().getOwner()
				.getId();
		int certId = data.get(position).getTrustedCertificate().getId();
		intent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID, ownerId);
		intent.putExtra(
				CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID, certId);
		context.startActivity(intent);

	}

}
