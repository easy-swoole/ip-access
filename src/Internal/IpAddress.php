<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Internal;

use InvalidArgumentException;
use LogicException;

/** @internal */
final class IpAddress
{
    private function __construct()
    {
    }

    /** 将 IP 文本转换为固定长度的二进制形式。 */
    public static function pack(string $ip): string
    {
        $packed = @inet_pton(trim($ip));
        if ($packed === false) {
            throw new InvalidArgumentException(sprintf('Invalid IP address: "%s".', $ip));
        }

        return $packed;
    }

    /** 将二进制 IP 转换为稳定的十六进制数组键。 */
    public static function key(string $packedIp): string
    {
        return bin2hex($packedIp);
    }

    /** 将经过校验的二进制 IP 转回规范化文本。 */
    public static function format(string $packedIp): string
    {
        $formatted = inet_ntop($packedIp);
        if ($formatted === false) {
            throw new LogicException('Unable to format the packed IP address.');
        }

        return $formatted;
    }
}
