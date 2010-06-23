<?php

/*

OAuthClient - A simple OAuth client for PHP, doing 3-legged auth
 
Copyright (c) 2010, Tuomas Rinta
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the software nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

class OAuthClient {
	
	private $oauth_token = null;
	private $oauth_token_secret = null;
	
	private $configuration = null;
	
	/**
	 * Get the OAuthClient instance.
	 * 
	 * The configuration should contain:
	 * * request_token_url: The URL to make the request for the request token
	 * * authorization_url: The URL to make the authorization calls to
	 * * access_token_url: The URL to make the access_token calls to
	 * * callback_url: The URL to use as callback base
	 * * oauth_consumer_key: The consumer key
	 * * oauth_consumer_secret: The consumer secret
	 */
	public function OAuthClient($conf) {
		$this->configuration = $conf;
	}
	
	/**
	 * Call a specific method
	 */
	public function call_method($method, $auth_token, $auth_secret, $method_params, $http_request_method = 'POST') {
		
		foreach($method_params as $key => $value) {
			unset($method_params[$key]);
			$method_params[urlencode($key)] = str_replace('+','%20', urlencode($value));
		}
		
		$this->oauth_token = $auth_token;
		$this->oauth_token_secret = $auth_secret;
		
		$d_params = array_merge(array(
				"oauth_consumer_key" => $this->configuration["oauth_consumer_key"],
				"oauth_nonce" => $this->generateNonce(),
				"oauth_signature_method" => "HMAC-SHA1",
				"oauth_timestamp" => time(),
				"oauth_version" => "1.0",
				"oauth_token" => $auth_token), $method_params);
				
		
		 return $this->query(
		 	$method,
		 	$this->buildURLString(
				$http_request_method,
				$method,
				$d_params
			),
			$method_params,
			$http_request_method
		);		
		
	}
	
	/**
	 * Get authorization for your application
	 */
	public function authorizeApp() {
		
		if(!empty($_REQUEST['oauth_verifier'])) {
			return $this->handle_callback();
		}
					
		// Auth not done
		// Build URL
		$results = array();
		parse_str(
			$this->query($this->configuration["request_token_url"],
			$this->buildURLString(
				"POST",
				$this->configuration["request_token_url"],
				array(
				"oauth_callback" => $this->configuration["callback_base"],
				"oauth_consumer_key" => $this->configuration["oauth_consumer_key"],
				"oauth_nonce" => $this->generateNonce(),
				"oauth_signature_method" => "HMAC-SHA1",
				"oauth_timestamp" => time(),
				"oauth_version" => "1.0")
		)), $results);
		
		$_SESSION['__oauth_token'] = $results["oauth_token"];
		$_SESSION['__oauth_token_secret'] = $results["oauth_token_secret"];
		
		// Authorize
		header("Location: " . $this->configuration["authorization_url"] . "?oauth_token=" . $results["oauth_token"]);
		
		exit();
		
	}
		
	private function query($url, $params, $post_body = array(), $http_request_method = 'POST') {
		
		$header_vars = array();
		foreach($params as $key => $value) {
			if(preg_match("#oauth_#", $key)) {
				$header_vars[] = $key . "=\"" . urlencode($value) . "\"";
			}
		}

		$header = sprintf("Authorization: OAuth %s\r\n", join($header_vars, ", "));
		
		$http = array('method' => $http_request_method, 'header' => $header);
		if(!empty($post_body)) {
			$http["content"] = urldecode(http_build_query($post_body));
		}
		
		$context = stream_context_create(
			array(
				"http" => $http
			)
		);
		

		return file_get_contents($url, false, $context);
		
	}
		

	
	private function handle_callback() {
				
		$this->oauth_token = $_REQUEST['oauth_token']; // $_SESSION['__oauth_token'];
		$this->oauth_token_secret = $_SESSION['__oauth_token_secret'];
		
		$results = array();
		parse_str($this->query(
			$this->configuration["access_token_url"],
			$this->buildURLString("POST",
			$this->configuration["access_token_url"],
			array(
				"oauth_consumer_key" => $this->configuration["oauth_consumer_key"],
				"oauth_nonce" => $this->generateNonce(),
				"oauth_token" => $this->oauth_token,
				"oauth_verifier" => $_REQUEST['oauth_verifier'],
				"oauth_signature_method" => "HMAC-SHA1",
				"oauth_timestamp" => time(),
				"oauth_version" => "1.0"
			)
		)), $results);
		
		return $results;
	
	}
	
	private function buildURLString($method, $url, $arr) {
		
		// Sort the array
		ksort($arr);
				
		// Encode url
		$encoded_url = urlencode($url);
		
		// Create the params
		$parameters = "";
		foreach($arr as $key => $value) {
			if($key == "oauth_callback") {
				$value = urlencode($value);
			}
			$parameters .= "$key=$value&";				
			
		}
		$parameters = urlencode(substr($parameters, 0, -1));
		
		$signature_base = "${method}&${encoded_url}&${parameters}";
		
		$composite_key = urlencode($this->configuration["oauth_consumer_secret"]) . "&" . $this->oauth_token_secret;
		
		$arr["oauth_signature"] = base64_encode(hash_hmac('sha1', $signature_base, $composite_key, true));
		
		return $arr;
		
	}
	
	private function generateNonce() {
		return uniqid(); 
	}

	
}

?>
