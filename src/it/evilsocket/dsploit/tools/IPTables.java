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

import it.evilsocket.dsploit.core.System;
import android.util.Log;

public class IPTables extends Tool
{			
	private static final String TAG = "IPTABLES";
	
	public IPTables( ){
		super( "iptables" );		
	}
	
	public void trafficRedirect( String to ) {
		Log.d( TAG, "Redirecting traffic to " + to );
		
		try
		{							
			super.run("-t nat -A PREROUTING -j DNAT -p tcp --to " + to );	
		}
		catch( Exception e )
		{
			System.errorLogging( TAG, e );
		}
	}
	
	public void undoTrafficRedirect( String to ) {
		Log.d( TAG, "Undoing traffic redirection" );
		
		try
		{
			super.run("-t nat -D PREROUTING -j DNAT -p tcp --to " + to );
		}
		catch( Exception e )
		{
			System.errorLogging( TAG, e );
		}
	}
		
	public void portRedirect( int from, int to ) {
		Log.d( TAG, "Redirecting traffic from port " + from + " to port " + to );
		
		try
		{							
			// clear nat
			super.run( "-t nat -F" );
			// clear
			super.run( "-F" );
			// post route
			super.run( "-t nat -I POSTROUTING -s 0/0 -j MASQUERADE" );
			// accept all
			super.run( "-P FORWARD ACCEPT" );
			// add rule
			super.run( "-t nat -A PREROUTING -j DNAT -p tcp --dport " + from + " --to " + System.getNetwork().getLocalAddressAsString() + ":" + to );	
		}
		catch( Exception e )
		{
			System.errorLogging( TAG, e );
		}
	}
	
	public void undoPortRedirect( int from, int to ){
		Log.d( TAG, "Undoing port redirection" );
		
		try
		{
			// clear nat
			super.run( "-t nat -F" );
			// clear
			super.run( "-F" );
			// remove post route
			super.run( "-t nat -D POSTROUTING -s 0/0 -j MASQUERADE" );
			// remove rule
			super.run( "-t nat -D PREROUTING -j DNAT -p tcp --dport " + from + " --to " + System.getNetwork().getLocalAddressAsString() + ":" + to );
		}
		catch( Exception e )
		{
			System.errorLogging( TAG, e );
		}
	}
	
}
