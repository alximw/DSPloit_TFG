/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package it.evilsocket.dsploit.plugins.mitm;

import it.evilsocket.dsploit.R;

import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.net.Endpoint;
import it.evilsocket.dsploit.plugins.mitm.SpoofSession.OnSessionReadyListener;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.ToggleButton;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;

public class ExtractorTargetChooser extends  SherlockActivity {

	static boolean DEBUG_ENABLED=false;
	
	 //views displayed on this activity
	private ToggleButton			startStopListing			=null;
	private ListView 				targetList					=null;
	
	//spoofSession object->create an ARP spoof session
	private SpoofSession			spoofSession				=null;

	
	//save the state of the target search
	private boolean lookingForTargets							=false;
	
	

	
	//This pcap filter will show only http traffic including its Ethernet header  
	private static final String PCAP_FILTER_HTTP= "-eA dst port 80 or dst port 443 or src port 80 or src port 443 ";
	

	/*
	 * This regex validates packet including Ethernet and IP header plus payload 
	 */
	static String regexc="^.+(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2}))\\s\\(.+\\s.+\\)\\s\\>\\s(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2}))." +
			"+length\\s+(\\d+)\\)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\s]+\\s+>\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\:]+:.+";
	
	//pattern  to compile regexc
	private static Pattern 			PARSER 	 					=null; 

	//Adapter object for listview
	private static EndPointTargetAdapter adapter				=null;
	

	
	/*
	 * This object will contain the information about the
	 * endpoints shown on the target list.
	 */
	public  class EndPointTarget extends Endpoint
	{
		public EndPointTarget(InetAddress address, byte[] hardware) {
			super(address, hardware);
		}
	
		public EndPointTarget(String address, String hardware) {
			super(address, hardware);
		}
	}
	

	
	public static class EndPointTargetAdapter extends ArrayAdapter<EndPointTarget>
	{
		int rowLayout;		//layout ID 
		Context adapterContext	=	null;	//context
		ArrayList<EndPointTarget> targetList;	//list of found targets
		
		//holder class which works as row view's cache
		static class ElementHolder{
			TextView macAddres;
			TextView IPAddres;
			TextView macVendor;
		}
		
		public EndPointTargetAdapter(Context context,int layout) {
			super(context, layout);
			this.adapterContext=context;
			this.rowLayout=layout;
			targetList	=	new ArrayList<EndPointTarget>();
		}
		
		public synchronized EndPointTarget getListElement(int index){
			EndPointTarget target=targetList.get(index);
			return target;
		}

		public int getCount(){
			return targetList.size();
		}
		public  View getView(int position, View convertView, ViewGroup parent) {
			
				//holder for the list element views
			ElementHolder holder;
				//convertView saves the view of the current element if it has benn inflated before
			View listElement=convertView;
							/*
				 * If this is the first time the element is inflated (convertiview==NULL)
				 * inflate it and create a new holder on which you can save the view references
				 * instead of search them in the layout tree.
				 */
			if(listElement==null)
			{
				LayoutInflater inflater=(LayoutInflater) adapterContext.getSystemService(LAYOUT_INFLATER_SERVICE);
				listElement=inflater.inflate(rowLayout, null,false );
				holder=new ElementHolder();
				holder.IPAddres=(TextView)listElement.findViewById(R.id.IPAddresField);
				holder.macAddres=(TextView)listElement.findViewById(R.id.MacAddresField);
				holder.macVendor=(TextView)listElement.findViewById(R.id.MacVendorField);
				listElement.setTag(holder);
			
			}else{
			
				// if the layout has been inflated before, we just retrieve the holder...
				 
				holder=(ElementHolder)listElement.getTag();	
			}
				
			
				//..and fill the views with our data.
			
			holder.IPAddres.setText(getListElement(position).getAddress().toString().replace("/", ""));
			holder.macAddres.setText(targetList.get(position).getHardwareAsString());
			if(System.getMacVendor(targetList.get(position).getHardware())==null)
			{
				holder.macVendor.setText("Unknown MAC vendor");	
			}else{
			holder.macVendor.setText(System.getMacVendor(targetList.get(position).getHardware()));
			}
			
			
			return listElement;
		}
		
		
		
		public synchronized void addTarget(EndPointTarget newtarget){
			boolean targetAdded=false;		
			for(EndPointTarget target:targetList){			
				if( target.getAddress().equals(newtarget.getAddress()) ){
					targetAdded=true;
					break;
				}		
			}			
			if(!targetAdded){ 
				targetList.add(newtarget);
			}
		}
		 
		
		
	}		
		
	
	
	
	
	
	
	
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
        setTitle( System.getCurrentTarget() + " > MITM > Target Chooser" );
        setContentView(R.layout.plugin_mitm_extractor);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        
        //initialize the activity views
        startStopListing =(ToggleButton)findViewById(R.id.startTargetListingButton);
        targetList =(ListView)findViewById(R.id.targetList);

        //set new OnclickListener for the button
        startStopListing.setOnClickListener(new OnClickListener() {			
        	@Override
        	public void onClick(View v) {	
        		if(lookingForTargets){
        			setStoppedState();
        		}else{
        			setStartedState();	
        		}
        	}
        });
        //compile the regular expression
        PARSER=Pattern.compile(regexc);
        
        //initialize the spoofSession object, not using proxy or server
        spoofSession	   = new SpoofSession( false, false, null, null );

        //create a new target list adapter
        adapter=new EndPointTargetAdapter(getApplicationContext(), R.layout.end_point_target_list_item);

        //set the adapter for the list
        targetList.setAdapter(adapter);

        //set new onItemselected for the listview
        targetList.setOnItemClickListener(new OnItemClickListener() {

			@Override
			public void onItemClick(AdapterView<?> arg0, View element, int position,long id) {
				//in case of active search, stop it
					setStoppedState();					
					Intent intent=new Intent(getApplicationContext(), Extractor.class);
					intent.putExtra("target_IP", adapter.getListElement(position).getAddress().toString().replace("/", ""));
					intent.putExtra("target_MAC", adapter.getListElement(position).getHardwareAsString());
					startActivity(intent);
			}
        });

	}


	

	private void setStartedState( ) {		
		//if the re is a tcpdump session alive, we first kill it
		System.getTcpDump().kill();
		lookingForTargets=true;
		spoofSession.start( new OnSessionReadyListener() {			
			@Override
			public void onError( String error ) {

			}
			
			@Override
			public void onSessionReady() {
				
				System.getTcpDump().sniff( PCAP_FILTER_HTTP, null, new OutputReceiver(){
					@Override
					public void onStart(String command) { }

					@Override
					public void onNewLine( String line ) {

						try
						{
							Matcher matcher = PARSER.matcher( line.trim() );

								if(matcher!=null && matcher.find()){
									EndPointTarget source= new EndPointTarget(matcher.group(8), matcher.group(1));
									EndPointTarget destiny= new EndPointTarget(matcher.group(9), matcher.group(4));
									
									if(System.getNetwork().isInternal(matcher.group(8))){
									//	showDebug("internal node (SRC)");
										//save it to the list
										final EndPointTarget target=source;
										
										ExtractorTargetChooser.this.runOnUiThread(new Runnable() {
											
											@Override
											public void run() {
												adapter.addTarget(target);
												adapter.notifyDataSetChanged();
												
											}
										});
									
									}
									
									if(System.getNetwork().isInternal(matcher.group(9))){
										
										//save it to the list
										final EndPointTarget target=destiny;
											
										ExtractorTargetChooser.this.runOnUiThread(new Runnable() {

											@Override
											public void run() {
												adapter.addTarget(target);
												adapter.notifyDataSetChanged();

											}
										});

									}
									
									
									
								}
							
						}
						catch( Exception e )
						{
							System.errorLogging( "Error during packet capturing", e );
						}
					}

					@Override
					public void onEnd(int exitCode) { }
				}).start();				
			}
		});
	

	}
	
	private void setStoppedState( ) {		
		//stop the current spoof session
		spoofSession.stop();
		//kill the current tcpdump session
		System.getTcpDump().kill();
		//update the search state
		lookingForTargets= false;
		//uncheck the start/stop button
		this.startStopListing.setChecked( false );                			
	}
	

	
	
	
	/*
	 * ->onOptionsItemSelected takes you to the parent activity when actionBar arrow is pressed
	 * 
	 * ->onbackPressed does the same but when  the back button on the device is pressed
	 * 
	 * @see com.actionbarsherlock.app.SherlockActivity#onOptionsItemSelected(android.view.MenuItem)
	 */
	
	public boolean onOptionsItemSelected( MenuItem item ) 
	{    
		switch( item.getItemId() ) 
		{        
			case android.R.id.home:            
	         
				onBackPressed();
				
				return true;
	    	  
			default:            
				return super.onOptionsItemSelected(item);    
	   }
	}
	
	public void onBackPressed() {
	    super.onBackPressed();
	    overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_left);	    	    
	}
}
