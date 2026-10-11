<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess;

use EasySwoole\IpAccess\Internal\IpAddress;
use EasySwoole\IpAccess\Internal\IpNetwork;
use LogicException;

final class IpAccess
{
    /** @var array<string, true> 使用二进制 IP 的十六进制字符串作为键，避免 IPv6 不同写法造成重复 */
    private array $whiteIps = [];

    /** @var array<string, true> */
    private array $blackIps = [];

    /** @var array<string, IpNetwork> */
    private array $whiteSegments = [];

    /** @var array<string, IpNetwork> */
    private array $blackSegments = [];

    public function addWhiteIp(string $ip): self
    {
        $normalized = IpAddress::pack($ip);
        $key = IpAddress::key($normalized);
        if (isset($this->blackIps[$key])) {
            throw new LogicException(sprintf(
                'IP "%s" conflicts with existing IP "%s" in the blacklist.',
                $ip,
                IpAddress::format($normalized)
            ));
        }
        $this->whiteIps[$key] = true;

        return $this;
    }

    public function addBlackIp(string $ip): self
    {
        $normalized = IpAddress::pack($ip);
        $key = IpAddress::key($normalized);
        if (isset($this->whiteIps[$key])) {
            throw new LogicException(sprintf(
                'IP "%s" conflicts with existing IP "%s" in the whitelist.',
                $ip,
                IpAddress::format($normalized)
            ));
        }
        $this->blackIps[$key] = true;

        return $this;
    }

    public function addWhiteIpSegment(string $segment): self
    {
        $network = IpNetwork::fromCidr($segment);
        $this->assertNoSegmentConflict($segment, $network, $this->blackSegments, 'blacklist');
        $this->whiteSegments[$network->key()] = $network;

        return $this;
    }

    public function addBlackIpSegment(string $segment): self
    {
        $network = IpNetwork::fromCidr($segment);
        $this->assertNoSegmentConflict($segment, $network, $this->whiteSegments, 'whitelist');
        $this->blackSegments[$network->key()] = $network;

        return $this;
    }

    public function isAllowAccess(string $ip): bool
    {
        $normalized = IpAddress::pack($ip);
        $key = IpAddress::key($normalized);

        // 精确 IP 规则优先于网段规则，从而允许在网段中设置单个 IP 例外。
        if (isset($this->whiteIps[$key])) {
            return true;
        }
        if (isset($this->blackIps[$key])) {
            return false;
        }
        foreach ($this->whiteSegments as $network) {
            if ($network->contains($normalized)) {
                return true;
            }
        }
        foreach ($this->blackSegments as $network) {
            if ($network->contains($normalized)) {
                return false;
            }
        }

        // 没有命中任何规则时采用默认放行策略。
        return true;
    }

    /** @param array<string, IpNetwork> $oppositeSegments */
    private function assertNoSegmentConflict(
        string $input,
        IpNetwork $candidate,
        array $oppositeSegments,
        string $oppositeList
    ): void {
        foreach ($oppositeSegments as $network) {
            if ($candidate->overlaps($network)) {
                throw new LogicException(sprintf(
                    'Segment "%s" overlaps existing segment "%s" in the %s.',
                    $input,
                    $network->format(),
                    $oppositeList
                ));
            }
        }
    }
}
