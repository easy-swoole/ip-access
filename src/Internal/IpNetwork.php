<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Internal;

use InvalidArgumentException;

/** 规范化的 CIDR 网段值对象。 @internal */
final class IpNetwork
{
    private string $network;
    private int $prefix;
    private int $bytes;

    private function __construct(string $network, int $prefix, int $bytes)
    {
        $this->network = $network;
        $this->prefix = $prefix;
        $this->bytes = $bytes;
    }

    /** 解析 CIDR 并清零主机位，确保同一网段只有一种内部表示。 */
    public static function fromCidr(string $segment): self
    {
        $parts = explode('/', trim($segment));
        if (count($parts) !== 2 || $parts[1] === '' || !ctype_digit($parts[1])) {
            throw new InvalidArgumentException(sprintf('Invalid CIDR segment: "%s".', $segment));
        }

        $ip = IpAddress::pack($parts[0]);
        $bytes = strlen($ip);
        $prefix = (int) $parts[1];
        $maxPrefix = $bytes * 8;
        if ($prefix > $maxPrefix) {
            throw new InvalidArgumentException(sprintf(
                'Invalid prefix length in "%s"; expected 0-%d.',
                $segment,
                $maxPrefix
            ));
        }

        return new self(self::applyMask($ip, $prefix), $prefix, $bytes);
    }

    /** 判断二进制 IP 是否属于当前网段。 */
    public function contains(string $packedIp): bool
    {
        return strlen($packedIp) === $this->bytes
            && self::applyMask($packedIp, $this->prefix) === $this->network;
    }

    /** 使用较短前缀重新取掩码，判断两个 CIDR 网段是否重叠。 */
    public function overlaps(self $other): bool
    {
        if ($this->bytes !== $other->bytes) {
            return false;
        }

        $commonPrefix = min($this->prefix, $other->prefix);

        return self::applyMask($this->network, $commonPrefix)
            === self::applyMask($other->network, $commonPrefix);
    }

    public function key(): string
    {
        return $this->bytes . ':' . bin2hex($this->network) . '/' . $this->prefix;
    }

    public function addressBytes(): int
    {
        return $this->bytes;
    }

    public function prefixLength(): int
    {
        return $this->prefix;
    }

    public function networkKey(): string
    {
        return bin2hex($this->network);
    }

    /**
     * 按指定前缀计算待检测 IP 的网络地址键。
     *
     * 网段索引按前缀分组，因此查询时每个已使用前缀只需要计算一次掩码。
     */
    public static function networkKeyFor(string $packedIp, int $prefix): string
    {
        return bin2hex(self::applyMask($packedIp, $prefix));
    }

    /** 返回规范化 CIDR，例如 192.168.1.31/24 会格式化为 192.168.1.0/24。 */
    public function format(): string
    {
        return IpAddress::format($this->network) . '/' . $this->prefix;
    }

    /** 对二进制 IP 应用前缀掩码，将剩余主机位清零。 */
    private static function applyMask(string $ip, int $prefix): string
    {
        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;
        $masked = substr($ip, 0, $fullBytes);

        if ($remainingBits > 0) {
            $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
            $masked .= chr(ord($ip[$fullBytes]) & $mask);
        }

        return str_pad($masked, strlen($ip), "\0");
    }
}
