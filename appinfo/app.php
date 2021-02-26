<?php

require(dirname(__FILE__) . "/../vendor/autoload.php");


function prepareUserLogin($user, $firstTimeLogin){
	OC::$server->getCsrfTokenManager()->refreshToken();
	OC_Util::setupFS($user->getUID());

	if($firstTimeLogin){
		$userFolder = OC::$server->getUserFolder($user->getUID());
		OC_Util::copySkeleton($user->getUID(), $userFolder);
	}
}
function getUserInfo(){
	$publickey = <<<EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraewUw7V1hiuSgUvkly9
X+tcIh0e/KKqeFnAo8WR3ez2tA0fGwM+P8sYKHIDQFX7ER0c+ecTiKpo/Zt/a6AO
gB/zHb8L4TWMr2G4q79S1gNw465/SEaGKR8hRkdnxJ6LXdDEhgrH2ZwIPzE0EVO1
eFrDms1jS3/QEyZCJ72oYbAErI85qJDF/y/iRgl04XBK6GLIW11gpf8KRRAh4vuh
g5/YhsWUdcX+uDVthEEEGOikSacKZMFGZNi8X8YVnRyWLf24QTJnTHEv+0EStNrH
HnxCPX0m79p7tBfFC2ha2OYfOtA+94ZfpZXUi2r6gJZ+dq9FWYyA0DkiYPUq9QMb
OQIDAQAB
-----END PUBLIC KEY-----
EOT;

	try {
		if(!isset($_COOKIE["traP_token"])){
			throw new Exception("No token");
		}
		$jwt = JWT::decode($_COOKIE["traP_token"], $publickey, array('RS256'));
	} catch(Exception $e) {
		header("Location: https://q.trap.jp/login?redirect=" . urlencode("https://" . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"] . "?" . $_SERVER["QUERY_STRING"]));
		exit;
	}

	return [
		"uid" => $jwt->id,
		"email" => $jwt->id . "@example.com",
		"displayName" => $jwt->id,
	];
}
function authWithTrapToken(){
	$session = OC::$server->getUserSession();

	if(!$session->isLoggedIn()){
		$token = getUserInfo();
		$userMan = OC::$server->getUserManager();
		$groupMan = OC::$server->getGroupManager();

		$user = $userMan->get($token["uid"]);
		if(!$user){
			$user = $userMan->createUser($token["uid"], random_bytes(256));
		}

		$user->setDisplayName($token["displayName"]);
		$user->setEMailAddress($token["email"]);

		$group = $groupMan->get("members");
		if(!$group){
			$group = $groupMan->createGroup("members");
		}

		if(!$group->inGroup($user)){
			$group->addUser($user);
		}

		$session->setUser($user);
		$session->setLoginName($user->getUID());
		prepareUserLogin($user, $user->updateLastLoginTimestamp());

		$session->createSessionToken(OC::$server->getRequest(), $user->getUID(), $user->getUID());
	}
}

if(strpos($_SERVER["REQUEST_URI"], "/login") === 0){
	authWithTrapToken();
}
