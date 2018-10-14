<?php

declare(strict_types=1);

namespace K911\Swoole\Tests\Unit\Server\Configurator;

use K911\Swoole\Server\Configurator\WithRequestHandler;
use K911\Swoole\Tests\Unit\Server\RequestHandler\RequestHandlerDummy;
use K911\Swoole\Tests\Unit\Server\SwooleHttpServerMock;
use PHPUnit\Framework\TestCase;

class WithRequestHandlerTest extends TestCase
{
    /**
     * @var RequestHandlerDummy
     */
    private $requestHandlerDummy;

    /**
     * @var ConfiguratorDummy
     */
    private $decoratedDummy;

    /**
     * @var WithRequestHandler
     */
    private $configurator;

    protected function setUp(): void
    {
        $this->requestHandlerDummy = new RequestHandlerDummy();
        $this->decoratedDummy = new ConfiguratorDummy();

        $this->configurator = new WithRequestHandler($this->decoratedDummy, $this->requestHandlerDummy);
    }

    public function testConfigure(): void
    {
        $serverMock = new SwooleHttpServerMock();

        $this->configurator->configure($serverMock);

        $this->assertTrue($serverMock->registeredEvent);
        $this->assertSame(['request', [$this->requestHandlerDummy, 'handle']], $serverMock->registeredEventPair);
    }
}