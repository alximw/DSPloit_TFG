package it.evilsocket.dsploit.plugins.mitm;

import it.evilsocket.dsploit.R;
import it.evilsocket.dsploit.core.System;
import android.os.Bundle;
import com.actionbarsherlock.app.SherlockActivity;

public class Extractor extends SherlockActivity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
        setTitle( System.getCurrentTarget() + " > MITM > Xtractor" );
        setContentView(R.layout.plugin_mitm_extractor);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);


	}

	
	
}
