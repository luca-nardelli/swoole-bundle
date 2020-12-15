<?php

declare(strict_types=1);

namespace K911\Swoole\Bridge\Symfony\HttpFoundation;

use RuntimeException;
use Swoole\Http\Response as SwooleResponse;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Response as HttpFoundationResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;

final class ResponseProcessor implements ResponseProcessorInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(HttpFoundationResponse $httpFoundationResponse, SwooleResponse $swooleResponse): void
    {
//        if ($httpFoundationResponse instanceof StreamedResponse) {
//            throw new RuntimeException('HttpFoundation "StreamedResponse" response object is not yet supported');
//        }

        foreach ($httpFoundationResponse->headers->allPreserveCaseWithoutCookies() as $name => $values) {
            $swooleResponse->header($name, \implode(', ', $values));
        }

        foreach ($httpFoundationResponse->headers->getCookies() as $cookie) {
            $swooleResponse->cookie(
                $cookie->getName(),
                $cookie->getValue() ?? '',
                $cookie->getExpiresTime(),
                $cookie->getPath(),
                $cookie->getDomain() ?? '',
                $cookie->isSecure(),
                $cookie->isHttpOnly(),
                $cookie->getSameSite() ?? ''
            );
        }

        $swooleResponse->status($httpFoundationResponse->getStatusCode());

        if ($httpFoundationResponse instanceof BinaryFileResponse) {
            $swooleResponse->sendfile($httpFoundationResponse->getFile()->getRealPath());
        } elseif ($httpFoundationResponse instanceof StreamedResponse) {
            // Workaround to access the callback directly
            $refClass = new \ReflectionClass($httpFoundationResponse);
            $prop = $refClass->getProperty('callback');
            $prop->setAccessible(true);
            $cb = $prop->getValue($httpFoundationResponse);
            $cb($swooleResponse);
            $swooleResponse->end();
        } else {
            $swooleResponse->end($httpFoundationResponse->getContent());
        }
    }
}
