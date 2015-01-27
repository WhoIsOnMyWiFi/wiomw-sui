
function check_wiomw_creds(username, passhash, agentkey, onValid, onInvalid) {
	var creds = {
		"username": username,
		"passhash": passhash,
		"agentkey": agentkey
	};
	
	//code requires jQuery 1.9.1 and jquery-json-2.4. to load correctly
	$.post( "https://www.whoisonmywifi.net/api/v100/rest/check_wiomw_creds", $.toJSON(creds) )
	.done(function( json_return_data ) {		
		//alert(json_return_data); //to see what is coming back from the server		
		var result = $.secureEvalJSON(json_return_data);//convert json to usable javascript object
		
		if(result.status === "OK")
		{	
			//alert(result.username + "_" + result.passhash + "_" + result.agentkey);
			onValid(result.username,result.passhash,result.agentkey);//if valid login, send values to Valid function
		}		
		else
		{
			//alert(result.error);//if invalid login, send blank to Invalid function
			onInvalid(result.error);
		}		
	});	
	
}

function setup_wiomw_agent(
		username,
		password,
		agentkey,
		agenttype,
		onValid,
		onInvalid
) {
	
	var creds = {
		"username": username,
		"password": password,
		"agentkey": agentkey,
		"agenttype": agenttype
	};
	
	//code requires jQuery 1.9.1 and jquery-json-2.4. to load correctly
	$.post( "https://www.whoisonmywifi.net/api/v100/rest/setup_wiomw_agent", $.toJSON(creds) )
	.done(function( json_return_data ) {		
		//alert(json_return_data); //to see what is coming back from the server		
		var result = $.secureEvalJSON(json_return_data);//convert json to usable javascript object
		
		if(result.status === "OK")
		{	
			//alert(result.username + "_" + result.passhash + "_" + result.agentkey);
			onValid(result.username,result.passhash,result.agentkey);//if valid login, send values to Valid function
		}		
		else
		{
			//alert(result.error);//if invalid login, send blank to Invalid function
			onInvalid(result.error);
		}		
	});
	

}

