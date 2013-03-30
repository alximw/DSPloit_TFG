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
package it.evilsocket.dsploit.tools;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.net.Target;
import android.content.Context;
import android.util.Log;

public class NMap extends Tool 
{
	private static final String TAG = "NMAP";
	
	public NMap( Context context ){
		super( "nmap/nmap", context );		
	}
	
	public static abstract class TraceOutputReceiver implements OutputReceiver
	{
		private static final Pattern HOP_PATTERN = Pattern.compile( "^(\\d+)\\s+(\\.\\.\\.|[0-9\\.]+\\s[ms]+)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}|[\\d]+).*", Pattern.CASE_INSENSITIVE );
		
		public void onStart( String commandLine ) { }
		
		public void onNewLine( String line ) {			
			Matcher matcher;
			
			if( ( matcher = HOP_PATTERN.matcher( line ) ) != null && matcher.find() )
			{
				onHop( matcher.group( 1 ), matcher.group( 2 ), matcher.group( 3 ) );
			}				
		}
		
		public void onEnd( int exitCode ) {
			if( exitCode != 0 )
				Log.e( TAG, "nmap exited with code " + exitCode );
		}
		
		public abstract void onHop( String hop, String time, String address );
	}
	
	public Thread trace( Target target, TraceOutputReceiver receiver ) {		
		return super.async( "-sn --traceroute --privileged --send-ip --system-dns " + target.getCommandLineRepresentation(), receiver );
	}
	
	public static abstract class SynScanOutputReceiver implements OutputReceiver
	{
		private static final Pattern PORT_PATTERN = Pattern.compile( "^discovered open port (\\d+)/([^\\s]+).+", Pattern.CASE_INSENSITIVE );
		
		public void onStart( String commandLine ) {
			
		}
		
		public void onNewLine( String line ) {			
			Matcher matcher;
			
			if( ( matcher = PORT_PATTERN.matcher( line ) ) != null && matcher.find() )
			{
				onPortFound( matcher.group( 1 ), matcher.group( 2 ) );
			}				
		}
		
		public void onEnd( int exitCode ) {
			if( exitCode != 0 )
				Log.e( TAG, "nmap exited with code " + exitCode );
		}
		
		public abstract void onPortFound( String port, String protocol );
	}
	
	public Thread synScan( Target target, SynScanOutputReceiver receiver, String custom ) {
		String command = "-sS -P0 --privileged --send-ip --system-dns -vvv ";
		
		if( custom != null )
			command += "-p " + custom + " ";
		
		command += target.getCommandLineRepresentation();
		
		return super.async( command, receiver );
	}
	
	public static abstract class InspectionReceiver implements OutputReceiver
	{
		private static final Pattern OPEN_PORT_PATTERN    = Pattern.compile( "^discovered open port (\\d+)/([^\\s]+).+", Pattern.CASE_INSENSITIVE );
		private static final Pattern SERVICE_PATTERN  	  = Pattern.compile( "^(\\d+)/([a-z]+)\\s+[a-z]+\\s+[a-z]+\\s+(.*)$", Pattern.CASE_INSENSITIVE );		
		private static final Pattern OS_PATTERN	   	      = Pattern.compile( "^Running:\\s+(.+)$", Pattern.CASE_INSENSITIVE );
		private static final Pattern OS_GUESS_PATTERN 	  = Pattern.compile( "^Running\\s+\\(JUST\\s+GUESSING\\):\\s+(.+)$", Pattern.CASE_INSENSITIVE );
		private static final Pattern SERVICE_INFO_PATTERN = Pattern.compile( "^Service\\s+Info:\\s+OS:\\s+([^;]+).*$", Pattern.CASE_INSENSITIVE );		
		private static final Pattern DEVICE_PATTERN       = Pattern.compile( "^Device\\s+type:\\s+(.+)$", Pattern.CASE_INSENSITIVE );
		
		public void onStart( String commandLine ) {
			
		}
		
		public void onNewLine( String line ) {			
			Matcher matcher = null;
			
			if( ( matcher = OPEN_PORT_PATTERN.matcher(line) ) != null && matcher.find() )
				onOpenPortFound( Integer.parseInt( matcher.group(1) ), matcher.group(2) );
			
			else if( ( matcher = SERVICE_PATTERN.matcher(line) ) != null && matcher.find() )
				onServiceFound( Integer.parseInt( matcher.group(1) ),  matcher.group(2), matcher.group(3) );
			
			else if( ( matcher = OS_PATTERN.matcher(line) ) != null && matcher.find() )
				onOsFound( matcher.group(1) );
			
			else if( ( matcher = OS_GUESS_PATTERN.matcher(line) ) != null && matcher.find() )
				onGuessOsFound( matcher.group(1) );
			
			else if( ( matcher = DEVICE_PATTERN.matcher(line) ) != null && matcher.find() )
				onDeviceFound( matcher.group(1).replace( "|", ",  ") );
			
			else if( ( matcher = SERVICE_INFO_PATTERN.matcher(line) ) != null && matcher.find() )
				onServiceInfoFound( matcher.group(1) );
		}
		
		public abstract void onOpenPortFound( int port, String protocol );
		public abstract void onServiceFound( int port, String protocol, String service );
		public abstract void onOsFound( String os );
		public abstract void onGuessOsFound( String os );
		public abstract void onDeviceFound( String device );
		public abstract void onServiceInfoFound( String info );

		public void onEnd( int exitCode ) {
			if( exitCode != 0 )
				Log.e( TAG, "nmap exited with code " + exitCode );
		}
	}
	
	public Thread inpsect( Target target, InspectionReceiver receiver ) {
		return super.async( "-T4 -F -O -sV --privileged --send-ip --system-dns -vvv " + target.getCommandLineRepresentation(), receiver );
	}
}
