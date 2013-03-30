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
package it.evilsocket.dsploit.plugins;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.R;
import it.evilsocket.dsploit.core.Plugin;
import it.evilsocket.dsploit.gui.dialogs.ErrorDialog;
import it.evilsocket.dsploit.net.Target;

public class RouterPwn extends Plugin
{
	public RouterPwn() {
		super
		( 
		    "Router PWN", 
		    "Launch the http://routerpwn.com/ service to pwn your router.", 
		    new Target.Type[]{ Target.Type.ENDPOINT }, 
		    Plugin.NO_LAYOUT,
		    R.drawable.action_routerpwn 
		);
	}
	
	@Override
	public boolean isAllowedTarget( Target target ){
		return target.isRouter();
	}	
	
	@Override
	public void onActionClick( Context context ){		
		try
		{
			String uri     = "http://routerpwn.com/";
			Intent browser = new Intent( Intent.ACTION_VIEW, Uri.parse( uri ) );
		
			context.startActivity( browser );
		}
		catch( ActivityNotFoundException e )
		{
			System.errorLogging( "ROUTERPWN", e );
			
			new ErrorDialog( "Error", "No activities to handle url opening!", ( Activity )context ).show();
		}
	}
}
