<?php
declare(strict_types=1);

namespace OCA\TrapAuth\AppInfo;

use Exception;
use OC\Security\CSRF\CsrfTokenManager;
use OC_Util;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IRequest;
use OCP\IUserManager;

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use OCP\IUserSession;

const publicKey = <<<EOT
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

class TrapAuth {
    /** @var IUserManager */
    private IUserManager $userManager;
    /** @var IGroupManager */
    private IGroupManager $groupManager;
    /** @var CsrfTokenManager */
    private CsrfTokenManager $csrfTokenManager;
    /** @var IRootFolder */
    private IRootFolder $rootFolder;
    /** @var IRequest */
    private IRequest $request;
    /** @var IUserSession */
    private IUserSession $session;
    /** @var IConfig */
    private IConfig $config;

    public function __construct(IUserManager $userManager,
                                IGroupManager $groupManager,
                                CsrfTokenManager $csrfTokenManager,
                                IRootFolder $rootFolder,
                                IRequest $request,
                                IUserSession $session,
                                IConfig $config) {
        $this->userManager = $userManager;
        $this->groupManager = $groupManager;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->rootFolder = $rootFolder;
        $this->request = $request;
        $this->session = $session;
        $this->config = $config;
    }

    private function getUserInfo(): array {
        try {
            $token = $this->request->getCookie("traP_token");
            if(is_null($token)){
                throw new Exception("No token");
            }
            if (str_contains($token, "=")) {
                throw new Exception("Invalid token");
            }
            $invalidate_tokens = explode(" ", $this->config->getSystemValueString("trap.invalidate_tokens"));
            if (in_array($token, $invalidate_tokens, true)) {
                throw new Exception("Invalid token");
            }
            $jwt = JWT::decode($token, new Key(publicKey, "RS256"));
        } catch(Exception $e) {
            header("Location: https://portal.trap.jp/login?redirect=" . urlencode("https://" . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"] . "?" . $_SERVER["QUERY_STRING"]));
            exit;
        }

        return [
            "uid" => $jwt->id,
            "email" => $jwt->id . "@example.com",
            "displayName" => $jwt->id,
        ];
    }

    private function prepareUserLogin($user, $firstTimeLogin) {
        $this->csrfTokenManager->refreshToken();
        OC_Util::setupFS($user->getUID());

        if ($firstTimeLogin) {
            $userFolder = $this->rootFolder->getUserFolder($user->getUID());
            OC_Util::copySkeleton($user->getUID(), $userFolder);
        }
    }

    public function authWithTrapToken() {
        if (strpos($this->request->getRequestUri(), "/login") !== 0) {
            return;
        }
        if ($this->session->isLoggedIn()) {
            return;
        }

        $token = $this->getUserInfo();

        $user = $this->userManager->get($token["uid"]);
        if (!$user) {
            $user = $this->userManager->createUser($token["uid"], random_bytes(256));
        }

        $user->setDisplayName($token["displayName"]);
        $user->setEMailAddress($token["email"]);

        $group = $this->groupManager->get("members");
        if (!$group) {
            $group = $this->groupManager->createGroup("members");
        }

        if (!$group->inGroup($user)) {
            $group->addUser($user);
        }

        $this->session->setUser($user);
        $this->session->setLoginName($user->getUID());
        $this->prepareUserLogin($user, $user->updateLastLoginTimestamp());

        $this->session->createSessionToken($this->request, $user->getUID(), $user->getUID());
    }
}
