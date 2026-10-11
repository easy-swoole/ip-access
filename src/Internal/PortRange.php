<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Internal;

use InvalidArgumentException;

/** 端口闭区间值对象。 @internal */
final class PortRange
{
    private int $start;
    private int $end;

    private function __construct(int $start, int $end)
    {
        $this->start = $start;
        $this->end = $end;
    }

    /** 未传结束端口时，将单端口规范化为 start=end 的闭区间。 */
    public static function from(int|string $startPort, int|string|null $endPort = null): self
    {
        $start = self::normalizePort($startPort);
        $end = $endPort === null ? $start : self::normalizePort($endPort);
        if ($start > $end) {
            throw new InvalidArgumentException(sprintf(
                'Invalid port range: start port %d is greater than end port %d.',
                $start,
                $end
            ));
        }

        return new self($start, $end);
    }

    /** 将整数或数字字符串规范化为有效端口。 */
    public static function normalizePort(int|string $port): int
    {
        if (is_string($port)) {
            $port = trim($port);
            if ($port === '' || !ctype_digit($port)) {
                throw new InvalidArgumentException(sprintf('Invalid port: "%s".', $port));
            }
            $port = (int) $port;
        }

        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException(sprintf('Invalid port: "%s"; expected 1-65535.', $port));
        }

        return $port;
    }

    public function contains(int $port): bool
    {
        return $port >= $this->start && $port <= $this->end;
    }

    /** 闭区间 [a,b] 与 [c,d] 相交的充要条件是 a <= d 且 c <= b。 */
    public function overlaps(self $other): bool
    {
        return $this->start <= $other->end && $other->start <= $this->end;
    }

    public function format(): string
    {
        return $this->start === $this->end
            ? (string) $this->start
            : $this->start . '-' . $this->end;
    }
}
