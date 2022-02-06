<?php
declare(strict_types=1);

namespace OCA\TrapAuth\AppInfo;

use OC\Security\CSRF\CsrfTokenManager;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;

const appName = 'nc-trapauth';

class Application extends App implements IBootstrap
{
    public function __construct(array $urlParams = [])
    {
        parent::__construct(appName, $urlParams);
    }

    public function register(IRegistrationContext $context): void
    {
        include_once __DIR__ . '/../../vendor/autoload.php';

        $context->registerService('TrapAuth', function (ContainerInterface $c) {
            return new TrapAuth(
                $c->get(IEventDispatcher::class),
                $c->get(IUserManager::class),
                $c->get(IGroupManager::class),
                $c->get(CsrfTokenManager::class),
                $c->get(IRootFolder::class),
                $c->get(IRequest::class),
                $c->get(IUserSession::class),
                $c->get(IConfig::class)
            );
        });
    }

    public function boot(IBootContext $context): void
    {
        $context->getAppContainer()->get('TrapAuth')->authWithTrapToken();
    }
}
