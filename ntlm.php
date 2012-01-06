<?php

// loune 25/3/2006, 22/08/2009, 20/09/2009
// For more information see:
// http://siphon9.net/loune/2009/09/ntlm-authentication-in-php-now-with-ntlmv2-hash-checking/
//

/*

php ntlm authentication library
Version 1.2

Copyright (c) 2009-2010 Loune Lam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Usage:

	include('ntlm.php');

	function get_ntlm_user_hash($user) {
		$userdb = array('loune'=>'test', 'user1'=>'password');
		
		if (!isset($userdb[strtolower($user)]))
			return false;	
		return ntlm_md4(ntlm_utf8_to_utf16le($userdb[strtolower($user)]));
	}

	session_start();
	$auth = ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", "get_ntlm_user_hash");

	if ($auth['authenticated']) {
		print "You are authenticated as $auth[username] from $auth[domain]/$auth[workstation]";
	}

To logout, use the code:

	ntlm_unset_auth();
	
SAMBA
-----	
To use this library with samba, please read the instructions inside verifyntlm.c 
to compile the verifyntlm helper. Use the ntlm.php library as above but omit the
get_ntlm_user_hash function and replace the ntlm_prompt line with this one:

	$auth = ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", null, "ntlm_verify_hash_smb");
	
For more, see http://siphon9.net/loune/2010/12/php-ntlm-integration-with-samba/

*/

$ntlm_verifyntlmpath = '/sbin/verifyntlm';

function ntlm_utf8_to_utf16le($str) {
	//$result = "";
	//for ($i = 0; $i < strlen($str); $i++)
	//    $result .= $str[$i]."\0";
	//return $result;
	return iconv('UTF-8', 'UTF-16LE', $str);
}

function ntlm_md4($s) {
	if (function_exists('mhash'))
		return mhash(MHASH_MD4, $s);
	return pack('H*', hash('md4', $s));
}

function ntlm_av_pair($type, $utf16) {
	return pack('v', $type).pack('v', strlen($utf16)).$utf16;
}

function ntlm_field_value($msg, $start, $decode_utf16 = true) {
	$len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
	$off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
	$result = substr($msg, $off, $len);
	if ($decode_utf16) {
		//$result = str_replace("\0", '', $result);
		$result = iconv('UTF-16LE', 'UTF-8', $result);
	}
	return $result;
}

function ntlm_hmac_md5($key, $msg) {
	$blocksize = 64;
	if (strlen($key) > $blocksize)
		$key = pack('H*', md5($key));
	
	$key = str_pad($key, $blocksize, "\0");
	$ipadk = $key ^ str_repeat("\x36", $blocksize);
	$opadk = $key ^ str_repeat("\x5c", $blocksize);
	return pack('H*', md5($opadk.pack('H*', md5($ipadk.$msg))));
}

function ntlm_get_random_bytes($length) {
	$result = "";
	for ($i = 0; $i < $length; $i++) {
		$result .= chr(rand(0, 255));
	}
	return $result;
}

function ntlm_get_challenge_msg($msg, $challenge, $targetname, $domain, $computer, $dnsdomain, $dnscomputer) {
	$domain = ntlm_field_value($msg, 16);
	$ws = ntlm_field_value($msg, 24);
	$tdata = ntlm_av_pair(2, ntlm_utf8_to_utf16le($domain)).ntlm_av_pair(1, ntlm_utf8_to_utf16le($computer)).ntlm_av_pair(4, ntlm_utf8_to_utf16le($dnsdomain)).ntlm_av_pair(3, ntlm_utf8_to_utf16le($dnscomputer))."\0\0\0\0\0\0\0\0";
	$tname = ntlm_utf8_to_utf16le($targetname);

	$msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
		pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
		"\x01\x02\x81\x00". // flags
		$challenge. // challenge
		"\x00\x00\x00\x00\x00\x00\x00\x00". // context
		pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
		$tname.$tdata;
	return $msg2;
}

function ntlm_verify_hash_smb($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash) {
	global $ntlm_verifyntlmpath;
	$cmd = bin2hex($challenge)." ".bin2hex(ntlm_utf8_to_utf16le(strtoupper($user)))." ".bin2hex(ntlm_utf8_to_utf16le($domain))." ".bin2hex(ntlm_utf8_to_utf16le($workstation))." ".bin2hex($clientblobhash)." ".bin2hex($clientblob);

	return (`$ntlm_verifyntlmpath $cmd` == "1\n");
}

function ntlm_verify_hash($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash) {

	$md4hash = $get_ntlm_user_hash($user);
	if (!$md4hash)
		return false;
	$ntlmv2hash = ntlm_hmac_md5($md4hash, ntlm_utf8_to_utf16le(strtoupper($user).$domain));
	$blobhash = ntlm_hmac_md5($ntlmv2hash, $challenge.$clientblob);
	
	/*
	print $domain ."<br>";
	print $user ."<br>";
	print bin2hex($challenge )."<br>";
	print bin2hex($clientblob )."<br>";
	print bin2hex($clientblobhash )."<br>";
	print bin2hex($md4hash )."<br>";
	print bin2hex($ntlmv2hash)."<br>";
	print bin2hex($blobhash)."<br>"; die; */

	return ($blobhash == $clientblobhash);
}

function ntlm_parse_response_msg($msg, $challenge, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback) {
	$user = ntlm_field_value($msg, 36);
	$domain = ntlm_field_value($msg, 28);
	$workstation = ntlm_field_value($msg, 44);
	$ntlmresponse = ntlm_field_value($msg, 20, false);
	//$blob = "\x01\x01\x00\x00\x00\x00\x00\x00".$timestamp.$nonce."\x00\x00\x00\x00".$tdata;
	$clientblob = substr($ntlmresponse, 16);
	$clientblobhash = substr($ntlmresponse, 0, 16);

	if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
		return array('authenticated' => false, 'error' => 'NTLMv2 response required. Please force your client to use NTLMv2.');
	}
	
	// print bin2hex($msg)."<br>";
	
	if (!$ntlm_verify_hash_callback($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback))
		return array('authenticated' => false, 'error' => 'Incorrect username or password.', 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
	return array('authenticated' => true, 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
}

function ntlm_unset_auth() {
	unset ($_SESSION['_ntlm_auth']);
}

function ntlm_prompt($targetname, $domain, $computer, $dnsdomain, $dnscomputer, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback = 'ntlm_verify_hash', $failmsg = "<h1>Authentication Required</h1>") {

	$auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
	if ($auth_header == null && function_exists('apache_request_headers')) {
		$headers = apache_request_headers();
		$auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
	}
	
	if (isset($_SESSION['_ntlm_auth']))
		return $_SESSION['_ntlm_auth'];
	
	// post data retention, looks like not needed	
	/*if ($_SERVER['REQUEST_METHOD'] == 'POST') {
		$_SESSION['_ntlm_post_data'] = $_POST;
	}*/
	
	if (!$auth_header) {
		header('HTTP/1.1 401 Unauthorized');
		header('WWW-Authenticate: NTLM');
		print $failmsg;
		exit;
	}

	if (substr($auth_header,0,5) == 'NTLM ') {
		$msg = base64_decode(substr($auth_header, 5));
		if (substr($msg, 0, 8) != "NTLMSSP\x00") {
			unset($_SESSION['_ntlm_post_data']);
			die('NTLM error header not recognised');
		}

		if ($msg[8] == "\x01") {
			$_SESSION['_ntlm_server_challenge'] = ntlm_get_random_bytes(8);
			header('HTTP/1.1 401 Unauthorized');
			$msg2 = ntlm_get_challenge_msg($msg, $_SESSION['_ntlm_server_challenge'], $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
			header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
			//print bin2hex($msg2);
			exit;
		}
		else if ($msg[8] == "\x03") {
			$auth = ntlm_parse_response_msg($msg, $_SESSION['_ntlm_server_challenge'], $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback);
			unset($_SESSION['_ntlm_server_challenge']);
			
			if (!$auth['authenticated']) {
				header('HTTP/1.1 401 Unauthorized');
				header('WWW-Authenticate: NTLM');
				//unset($_SESSION['_ntlm_post_data']);
				print $failmsg;
				print $auth['error'];
				exit;
			}
			
			// post data retention looks like not needed
			/*if (isset($_SESSION['_ntlm_post_data'])) {
				foreach ($_SESSION['_ntlm_post_data'] as $k => $v) {
					$_REQUEST[$k] = $v;
					$_POST[$k] = $v;
				}
				$_SERVER['REQUEST_METHOD'] = 'POST';
				unset($_SESSION['_ntlm_post_data']);
			}*/
			
			$_SESSION['_ntlm_auth'] = $auth;
			return $auth;
		}
	}
}


?>
