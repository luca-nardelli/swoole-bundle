<?php

declare(strict_types=1);

namespace K911\Swoole\Bridge\Symfony\Bundle\DependencyInjection;

use Assert\Assertion;
use Doctrine\ORM\EntityManagerInterface;
use K911\Swoole\Bridge\Doctrine\ORM\EntityManagerHandler;
use K911\Swoole\Bridge\Symfony\HttpFoundation\CloudFrontRequestFactory;
use K911\Swoole\Bridge\Symfony\HttpFoundation\RequestFactoryInterface;
use K911\Swoole\Bridge\Symfony\HttpFoundation\Session\SetSessionCookieEventListener;
use K911\Swoole\Bridge\Symfony\HttpFoundation\TrustAllProxiesRequestHandler;
use K911\Swoole\Bridge\Symfony\HttpKernel\DebugHttpKernelRequestHandler;
use K911\Swoole\Bridge\Symfony\HttpKernel\HttpKernelRequestHandler;
use K911\Swoole\Bridge\Symfony\Messenger\SwooleServerTaskTransportFactory;
use K911\Swoole\Bridge\Symfony\Messenger\SwooleServerTaskTransportHandler;
use K911\Swoole\Server\Config\Socket;
use K911\Swoole\Server\Config\Sockets;
use K911\Swoole\Server\Configurator\ConfiguratorInterface;
use K911\Swoole\Server\HttpServer;
use K911\Swoole\Server\HttpServerConfiguration;
use K911\Swoole\Server\RequestHandler\AdvancedStaticFilesServer;
use K911\Swoole\Server\RequestHandler\ExceptionHandler\ExceptionHandlerInterface;
use K911\Swoole\Server\RequestHandler\ExceptionHandler\JsonExceptionHandler;
use K911\Swoole\Server\RequestHandler\ExceptionHandler\ProductionExceptionHandler;
use K911\Swoole\Server\RequestHandler\RequestHandlerInterface;
use K911\Swoole\Server\Runtime\BootableInterface;
use K911\Swoole\Server\Runtime\HMR\HotModuleReloaderInterface;
use K911\Swoole\Server\Runtime\HMR\InotifyHMR;
use K911\Swoole\Server\ServerInterface;
use K911\Swoole\Server\ServerProxy;
use K911\Swoole\Server\TaskHandler\TaskHandlerInterface;
use K911\Swoole\Server\WorkerHandler\HMRWorkerStartHandler;
use K911\Swoole\Server\WorkerHandler\WorkerStartHandlerInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Transport\TransportFactoryInterface;

final class SwooleExtension extends Extension implements PrependExtensionInterface
{
    private $predefinedParents = [
        'http' => [
            'class' => HttpKernelRequestHandler::class,
            'definition' => [], // symfony DI service definition changes
            'config' => [], // swoole bundle item config changes on child (listener/handler)
        ],
    ];

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container): void
    {
    }

    /**
     * {@inheritdoc}
     *
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = Configuration::fromTreeBuilder();
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yaml');
        $loader->load('commands.yaml');
        $loader->load('server.yaml');

        $container->registerForAutoconfiguration(BootableInterface::class)
            ->addTag('swoole_bundle.bootable_service')
        ;
        $container->registerForAutoconfiguration(ConfiguratorInterface::class)
            ->addTag('swoole_bundle.server_configurator')
        ;

        $config = $this->processConfiguration($configuration, $configs);

        $this->registerServer($config['server'], $container);
        $this->registerHttpServer($config['http_server'], $container);

        if (\interface_exists(TransportFactoryInterface::class)) {
            $this->registerSwooleServerTransportConfiguration($container);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return 'swoole';
    }

    /**
     * {@inheritdoc}
     */
    public function getConfiguration(array $config, ContainerBuilder $container): Configuration
    {
        return Configuration::fromTreeBuilder();
    }

    /**
     * @throws \Symfony\Component\DependencyInjection\Exception\ServiceNotFoundException
     */
    private function registerHttpServer(array $config, ContainerBuilder $container): void
    {
        $this->registerHttpServerServices($config['services'], $container);
        $this->registerExceptionHandler($config['exception_handler'], $container);

        $container->setParameter('swoole.http_server.trusted_proxies', $config['trusted_proxies']);
        $container->setParameter('swoole.http_server.trusted_hosts', $config['trusted_hosts']);
        $container->setParameter('swoole.http_server.api.host', $config['api']['host']);
        $container->setParameter('swoole.http_server.api.port', $config['api']['port']);

        $this->registerHttpServerConfiguration($config, $container);
    }

    private function registerExceptionHandler(array $config, ContainerBuilder $container): void
    {
        [
            'handler_id' => $handlerId,
            'type' => $type,
            'verbosity' => $verbosity,
        ] = $config;

        if ('auto' === $type) {
            $type = $this->isProd($container) ? 'production' : 'json';
        }

        switch ($type) {
            case 'json':
                $class = JsonExceptionHandler::class;

                break;
            case 'custom':
                $class = $handlerId;

                break;
            default: // case 'production'
                $class = ProductionExceptionHandler::class;

                break;
        }

        $container->setAlias(ExceptionHandlerInterface::class, $class);

        if ('auto' === $verbosity) {
            if ($this->isProd($container)) {
                $verbosity = 'production';
            } elseif ($this->isDebug($container)) {
                $verbosity = 'trace';
            } else {
                $verbosity = 'verbose';
            }
        }

        $container->getDefinition(JsonExceptionHandler::class)
            ->setArgument('$verbosity', $verbosity)
        ;
    }

    private function registerSwooleServerTransportConfiguration(ContainerBuilder $container): void
    {
        $container->register(SwooleServerTaskTransportFactory::class)
            ->addTag('messenger.transport_factory')
            ->addArgument(new Reference(HttpServer::class))
        ;

        $container->register(SwooleServerTaskTransportHandler::class)
            ->addArgument(new Reference(MessageBusInterface::class))
            ->addArgument(new Reference(SwooleServerTaskTransportHandler::class.'.inner'))
            ->setDecoratedService(TaskHandlerInterface::class, null, -10)
        ;
    }

    private function registerHttpServerConfiguration(array $config, ContainerBuilder $container): void
    {
        [
            'static' => $static,
            'api' => $api,
            'hmr' => $hmr,
            'host' => $host,
            'port' => $port,
            'running_mode' => $runningMode,
            'socket_type' => $socketType,
            'ssl_enabled' => $sslEnabled,
            'settings' => $settings,
        ] = $config;

        if ('auto' === $static['strategy']) {
            $static['strategy'] = $this->isDebugOrNotProd($container) ? 'advanced' : 'off';
        }

        if ('advanced' === $static['strategy']) {
            $container->register(AdvancedStaticFilesServer::class)
                ->addArgument(new Reference(AdvancedStaticFilesServer::class.'.inner'))
                ->addArgument(new Reference(HttpServerConfiguration::class))
                ->addTag('swoole_bundle.bootable_service')
                ->setDecoratedService(RequestHandlerInterface::class, null, -60)
            ;
        }

        $settings['serve_static'] = $static['strategy'];
        $settings['public_dir'] = $static['public_dir'];

        if ('auto' === $settings['log_level']) {
            $settings['log_level'] = $this->isDebug($container) ? 'debug' : 'notice';
        }

        if ('auto' === $hmr) {
            $hmr = $this->resolveAutoHMR();
        }

        $sockets = $container->getDefinition(Sockets::class)
            ->addArgument(new Definition(Socket::class, [$host, $port, $socketType, $sslEnabled]))
        ;

        if ($api['enabled']) {
            $sockets->addArgument(new Definition(Socket::class, [$api['host'], $api['port']]));
        }

        $container->getDefinition(HttpServerConfiguration::class)
            ->addArgument(new Reference(Sockets::class))
            ->addArgument($runningMode)
            ->addArgument($settings)
        ;

        $this->registerHttpServerHMR($hmr, $container);
    }

    private function registerHttpServerHMR(string $hmr, ContainerBuilder $container): void
    {
        if ('off' === $hmr || !$this->isDebug($container)) {
            return;
        }

        if ('inotify' === $hmr) {
            $container->register(HotModuleReloaderInterface::class, InotifyHMR::class)
                ->addTag('swoole_bundle.bootable_service')
            ;
        }

        $container->autowire(HMRWorkerStartHandler::class)
            ->setPublic(false)
            ->setAutoconfigured(true)
            ->setArgument('$decorated', new Reference(HMRWorkerStartHandler::class.'.inner'))
            ->setDecoratedService(WorkerStartHandlerInterface::class)
        ;
    }

    private function resolveAutoHMR(): string
    {
        if (\extension_loaded('inotify')) {
            return 'inotify';
        }

        return 'off';
    }

    /**
     * Registers optional http server dependencies providing various features.
     */
    private function registerHttpServerServices(array $config, ContainerBuilder $container): void
    {
        // RequestFactoryInterface
        // -----------------------
        if ($config['cloudfront_proto_header_handler']) {
            $container->register(CloudFrontRequestFactory::class)
                ->addArgument(new Reference(CloudFrontRequestFactory::class.'.inner'))
                ->setAutowired(true)
                ->setAutoconfigured(true)
                ->setPublic(false)
                ->setDecoratedService(RequestFactoryInterface::class, null, -10)
            ;
        }

        // RequestHandlerInterface
        // -------------------------
        if ($config['trust_all_proxies_handler']) {
            $container->register(TrustAllProxiesRequestHandler::class)
                ->addArgument(new Reference(TrustAllProxiesRequestHandler::class.'.inner'))
                ->addTag('swoole_bundle.bootable_service')
                ->setDecoratedService(RequestHandlerInterface::class, null, -10)
            ;
        }

        if ($config['entity_manager_handler'] || (null === $config['entity_manager_handler'] && \interface_exists(EntityManagerInterface::class) && $this->isBundleLoaded($container, 'doctrine'))) {
            $container->register(EntityManagerHandler::class)
                ->addArgument(new Reference(EntityManagerHandler::class.'.inner'))
                ->setAutowired(true)
                ->setAutoconfigured(true)
                ->setPublic(false)
                ->setDecoratedService(RequestHandlerInterface::class, null, -20)
            ;
        }

        if ($config['debug_handler'] || (null === $config['debug_handler'] && $this->isDebug($container))) {
            $container->register(DebugHttpKernelRequestHandler::class)
                ->addArgument(new Reference(DebugHttpKernelRequestHandler::class.'.inner'))
                ->setAutowired(true)
                ->setAutoconfigured(true)
                ->setPublic(false)
                ->setDecoratedService(RequestHandlerInterface::class, null, -50)
            ;
        }

        if ($config['session_cookie_event_listener']) {
            $container->register(SetSessionCookieEventListener::class)
                ->setAutowired(true)
                ->setAutoconfigured(true)
                ->setPublic(false)
            ;
        }
    }

    private function isBundleLoaded(ContainerBuilder $container, string $bundleName): bool
    {
        $bundles = $container->getParameter('kernel.bundles');

        $bundleNameOnly = \str_replace('bundle', '', \mb_strtolower($bundleName));
        $fullBundleName = \ucfirst($bundleNameOnly).'Bundle';

        return isset($bundles[$fullBundleName]);
    }

    private function isProd(ContainerBuilder $container): bool
    {
        return 'prod' === $container->getParameter('kernel.environment');
    }

    private function isDebug(ContainerBuilder $container): bool
    {
        return $container->getParameter('kernel.debug');
    }

    private function isDebugOrNotProd(ContainerBuilder $container): bool
    {
        return $this->isDebug($container) || !$this->isProd($container);
    }

    private function configureSocketDefinition(Definition $socketDef, array $config): void
    {
        $socketDef->setArguments([
            '$host' => $config['socket']['host'],
            '$port' => $config['socket']['port'],
            '$type' => $config['socket']['type'],
            '$encryption' => $config['encryption']['enabled'],
        ]);
    }

    private function mergeListenerToConfig(array $config, array $listener): array
    {
//        $isListenerConfig = !isset($config['running_mode']);
        [
            'encryption' => $encryption,
            'http' => $http,
            'websocket' => $websocket,
        ] = $listener;

        if ($websocket['enabled']) {
            $config['open_websocket_protocol'] = true;
        }

        if ($http['enabled']) {
            $config['open_http_protocol'] = true;
            if ($http['http2']) {
                $config['open_http2_protocol'] = true;
            }
        }

        if ($encryption['enabled']) {
            /* @see swoole-src/swoole_server_port.cc#525 */
            /* @see swoole-src/swoole_runtime.cc#1007 */

            if (!empty($encryption['certificate_authority'])) {
                if (!empty($encryption['certificate_authority']['file'])) {
                    $config['ssl_cafile'] = $encryption['file'];
                } elseif (!empty($encryption['certificate_authority']['path'])) {
                    $config['ssl_capath'] = $encryption['path'];
                }
            }

            if (!empty($encryption['server_certificate'])) {
                $config['ssl_cert_file'] = $encryption['server_certificate']['file'];
                $config['ssl_key_file'] = $encryption['server_certificate']['key']['file'];
                if (!empty($encryption['server_certificate']['key']['passphrase'])) {
                    $config['ssl_passphrase'] = $encryption['server_certificate']['key']['passphrase'];
                }
            }

            if (!empty($encryption['client_certificate'])) {
                $config['ssl_client_cert_file'] = $encryption['client_certificate']['file'];
                $config['ssl_allow_self_signed'] = $encryption['client_certificate']['insecure'] ?? false;

                if ($encryption['client_certificate']['verify']['enabled']) {
                    $config['ssl_verify_peer'] = true;
                    if (!empty($encryption['client_certificate']['verify']['depth'])) {
                        $config['ssl_verify_depth'] = $encryption['client_certificate']['verify']['depth'];
                    }
                }
            }

//            $config['ssl_disable_compression'] = $listener['encryption']['xxx'];
//            $config['ssl_host_name'] = $listener['encryption']['xxx'];
            if (!empty($encryption['ciphers'])) {
                $config['ssl_ciphers'] = $encryption['ciphers'];
            }
        }

        return $config;
    }

    private function registerServerService(ContainerBuilder $container): Definition
    {
        $serverFactoryReference = new Reference('swoole_bundle.server.factory');

        $definition = $container->register('swoole_bundle.server');

        if ($this->proxyManagerInstalled()) {
            $definition->setClass(ServerInterface::class)
                ->setLazy(true)
                ->setFactory([$serverFactoryReference, 'make'])
            ;
        } else {
            $definition->setClass(ServerProxy::class)
                ->setArgument('$factory', $serverFactoryReference)
            ;
        }

        return $definition;
    }

    private function registerServer(array $server, ContainerBuilder $container): void
    {
        $serverDefinition = $this->registerServerService($container);

        $serverConfig = $server['config'];

        $mainSocketDefinition = $container->getDefinition('swoole_bundle.server.main_socket');
        $this->configureSocketDefinition($mainSocketDefinition, $server);

        $listenersDefinition = $container->getDefinition('swoole_bundle.server.listeners');
        $callbacksDefinition = $container->getDefinition('swoole_bundle.server.callbacks');

        $serverConfigDefinition = $container->getDefinition('swoole_bundle.server.config');

        $serverConfigDefinition->setArguments([
            '$runningMode' => $server['running_mode'],
            '$config' => $this->mergeListenerToConfig($serverConfig, $server),
        ]);
    }

    private function resolveParent(array $child, array $predefinedParents): ?array
    {
        if (!empty($child['parent'])) {
            Assertion::keyExists($predefinedParents, $child['parent']);

            return $predefinedParents[$child['parent']];
        }

        return null;
    }

    private function resolveDefinition(string $id, ?string $class, ContainerBuilder $container): Definition
    {
        if ($container->hasDefinition($id)) {
            $definition = $container->getDefinition($id);
            if (null !== $class) {
                Assertion::same($definition->getClass(), $class);
            }

            return $definition;
        }

        Assertion::notEmpty($class);
        Assertion::classExists($class);

        return $container->register($id, $class);
    }

    private function prepareDefinitions(array $children, ContainerBuilder $container, string $idPrefix = 'swoole_bundle.server.listeners.listener', array $predefinedParents = []): \Generator
    {
        $generatedIdCounter = 0;
        foreach ($children as $child) {
            $definitionId = $child['id'] ?? \sprintf('%s_%d', $idPrefix, ++$generatedIdCounter);
            $parent = $this->resolveParent($child, $predefinedParents);
            $definition = $this->resolveDefinition($definitionId, $parent['class'] ?? null, $container);

            if (!empty($parent['definition'])) {
                $definition->setChanges($parent['definition']);
            }

            if (!empty($parent['config'])) {
                $child = \array_merge($parent, $child);
            }
        }
    }

    private function proxyManagerInstalled(): bool
    {
        // If symfony/proxy-manager-bridge is installed this class exists
        return \class_exists(\Symfony\Bridge\ProxyManager\LazyProxy\Instantiator\RuntimeInstantiator::class);
    }
}
