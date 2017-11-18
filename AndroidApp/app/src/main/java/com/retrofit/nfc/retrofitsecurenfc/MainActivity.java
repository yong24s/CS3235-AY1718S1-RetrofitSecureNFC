package com.retrofit.nfc.retrofitsecurenfc;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.app.Activity;
import android.nfc.NfcAdapter;
import android.widget.TextView;
import android.widget.Toast;

import android.app.PendingIntent;
import android.content.IntentFilter;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.os.AsyncTask;
import android.util.Log;

public class MainActivity extends AppCompatActivity {
    public static final String MIME_TEXT_PLAIN = "text/plain";

    private TextView mTextView;
    private NfcAdapter mNfcAdapter;

    private void init() {
//        String[] keys = this.getResources().getStringArray(R.array.publickeys_domain);
//        String[] values = this.getResources().getStringArray(R.array.publickeys_p_g_h);
//
//        publicKeyMap = new LinkedHashMap<String,PublicKey>();
//
//        for (int i = 0; i < Math.min(keys.length, values.length); ++i) {
//            publicKeyMap.put(keys[i], new PublicKey(values[i]));
//        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mTextView = (TextView) findViewById(R.id.textView_explanation);
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (mNfcAdapter == null) {
            // Stop here, we definitely need NFC
            Toast.makeText(this, "This device doesn't support NFC.", Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        if (!mNfcAdapter.isEnabled()) {
            mTextView.setText("NFC is disabled.");
        }

//        init();
        handleIntent(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();

        /**
         * It's important, that the activity is in the foreground (resumed). Otherwise
         * an IllegalStateException is thrown.
         */
        //mNfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFiltersArray, techListsArray);
        setupForegroundDispatch(this, mNfcAdapter);
    }

    @Override
    protected void onPause() {
        /**
         * Call this before onPause, otherwise an IllegalArgumentException is thrown as well.
         */
        stopForegroundDispatch(this, mNfcAdapter);
        super.onPause();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        /**
         * This method gets called, when a new Intent gets associated with the current activity instance.
         * Instead of creating a new activity, onNewIntent will be called. For more information have a look
         * at the documentation.
         *
         * In our case this method gets called, when the user attaches a Tag to the device.
         */
        handleIntent(intent);
    }

    /**
     * @param activity The corresponding {@link Activity} requesting the foreground dispatch.
     * @param adapter The {@link NfcAdapter} used for the foreground dispatch.
     */
    public static void setupForegroundDispatch(final Activity activity, NfcAdapter adapter) {
        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        IntentFilter ndefDetected = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        IntentFilter techDetected = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);

        IntentFilter[] nfcIntentFilter = new IntentFilter[]{techDetected,tagDetected,ndefDetected};
        PendingIntent pendingIntent = PendingIntent.getActivity(
                activity, 0, new Intent(activity, activity.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        adapter.enableForegroundDispatch(activity, pendingIntent, nfcIntentFilter, null);

//        final Intent intent = new Intent(activity.getApplicationContext(), activity.getClass());
//        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
//
//        final PendingIntent pendingIntent =
//                PendingIntent.getActivity(activity.getApplicationContext(), 0, intent, 0);
//
//        IntentFilter[] filters = new IntentFilter[1];
//        String[][] techList = new String[][]{};
//
//        // Notice that this is the same filter as in our manifest.
//        filters[0] = new IntentFilter();
//        filters[0].addAction(NfcAdapter.ACTION_NDEF_DISCOVERED);
//        filters[0].addCategory(Intent.CATEGORY_DEFAULT);
//
//        try {
//            filters[0].addDataType("*/*");
//        } catch (MalformedMimeTypeException e) {
//            throw new RuntimeException("Check your mime type.");
//        }
//
//        adapter.enableForegroundDispatch(activity, pendingIntent, filters, techList);
    }

    /**
     * @param activity The corresponding {@link BaseActivity} requesting to stop the foreground dispatch.
     * @param adapter The {@link NfcAdapter} used for the foreground dispatch.
     */
    public static void stopForegroundDispatch(final Activity activity, NfcAdapter adapter) {
        adapter.disableForegroundDispatch(activity);
    }

    private void handleIntent(Intent intent) {
        String action = intent.getAction();

//        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {
//            Toast.makeText(MainActivity.this, "NDEF", Toast.LENGTH_SHORT).show();
//
//            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
//            new NdefReaderTask(this).execute(tag);
//        } else if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
//            Toast.makeText(MainActivity.this, "TECH", Toast.LENGTH_SHORT).show();
//
//            // In case we would still use the Tech Discovered Intent
//            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
//            String[] techList = tag.getTechList();
//            String searchedTech = Ndef.class.getName();
//
//            for (String tech : techList) {
//                if (searchedTech.equals(tech)) {
//                    new NdefReaderTask(this).execute(tag);
//                    break;
//                }
//            }
//        }

        switch (action) {
            case NfcAdapter.ACTION_TAG_DISCOVERED :
            case NfcAdapter.ACTION_NDEF_DISCOVERED :
            case NfcAdapter.ACTION_TECH_DISCOVERED :
                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                new NdefReaderTask(this).execute(tag);
        }
    }

    private class NdefReaderTask extends AsyncTask<Tag, Void, String> {

        private Context context;

        public NdefReaderTask (Context context) {
            this.context = context;
        }

        @Override
        protected String doInBackground(Tag... params) {
            Tag tag = params[0];

            Ndef ndef = Ndef.get(tag);

            if (ndef == null) {
                // NDEF is not supported by this Tag.
                return null;
            }

            NdefMessage ndefMessage = ndef.getCachedNdefMessage();
            NdefRecord[] records = ndefMessage.getRecords();

            for (NdefRecord ndefRecord : records) {
                try {
                    if (ndefRecord.getTnf() == NdefRecord.TNF_WELL_KNOWN && Arrays.equals(ndefRecord.getType(), NdefRecord.RTD_TEXT)) {
                        return readText(ndefRecord);
                    } else if (ndefRecord.getTnf() == NdefRecord.TNF_WELL_KNOWN && Arrays.equals(ndefRecord.getType(), NdefRecord.RTD_URI)) {
                        return readURL(ndefRecord);
                    }
                } catch (UnsupportedEncodingException e) {
                    Log.e("RetrofitSecureNFC", "Unsupported Encoding", e);
                }
            }
            return null;
        }

        private String readText(NdefRecord record) throws UnsupportedEncodingException {
        /*
         * See NFC forum specification for "Text Record Type Definition" at 3.2.1
         *
         * http://www.nfc-forum.org/specs/
         *
         * bit_7 defines encoding
         * bit_6 reserved for future use, must be 0
         * bit_5..0 length of IANA language code
         */

            byte[] payload = record.getPayload();

            // Get the Text Encoding
            String textEncoding = ((payload[0] & 128) == 0) ? "UTF-8" : "UTF-16";

            // Get the Language Code
            int languageCodeLength = payload[0] & 0063;

            // String languageCode = new String(payload, 1, languageCodeLength, "US-ASCII");
            // e.g. "en"

            // Get the Text
            return new String(payload, languageCodeLength + 1, payload.length - languageCodeLength - 1, textEncoding);
        }

        private String readURL(NdefRecord record) throws UnsupportedEncodingException {
            Uri url = record.toUri();

            ECDSAVerifier verifier = new ECDSAVerifier(context);

            if (verifier.verify(url.toString())) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        Toast.makeText(MainActivity.this, ":D This NFC Tag is verified! Opening it...", Toast.LENGTH_LONG).show();
                    }
                });

                Intent launchBrowser = new Intent(Intent.ACTION_VIEW, url);
                startActivity(launchBrowser);
            } else {
                runOnUiThread(new Runnable() {
                    public void run() {
                        Toast.makeText(MainActivity.this, ":( This NFC Tag cannot be verified...", Toast.LENGTH_LONG).show();
                    }
                });
            }

            return url.toString();
        }

        @Override
        protected void onPostExecute(String result) {
            if (result != null) {
                mTextView.setText("Read content: " + result);
            }
        }
    }
}
