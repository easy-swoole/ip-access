<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess;

use EasySwoole\IpAccess\Internal\IpAddress;
use EasySwoole\IpAccess\Internal\IpNetwork;
use EasySwoole\IpAccess\Internal\PortRange;
use LogicException;

final class IpPortAccess
{
    /** @var array<string, array<int, PortRange>> 以规范化 IP 为键保存端口闭区间 */
    private array $ipAllowRules = [];

    /** @var array<string, array<int, PortRange>> */
    private array $ipBlockRules = [];

    /** @var array<int, array{network: IpNetwork, ports: PortRange}> */
    private array $segmentAllowRules = [];

    /** @var array<int, array{network: IpNetwork, ports: PortRange}> */
    private array $segmentBlockRules = [];

    /** @var array<int, array<int, array<string, array<int, PortRange>>>> */
    private array $segmentAllowIndex = [];

    /** @var array<int, array<int, array<string, array<int, PortRange>>>> */
    private array $segmentBlockIndex = [];

    public function addIpAllowPort(string $ip, int|string $startPort, int|string|null $endPort = null): self
    {
        return $this->addIpRule($ip, $startPort, $endPort, true);
    }

    public function addIpBlockPort(string $ip, int|string $startPort, int|string|null $endPort = null): self
    {
        return $this->addIpRule($ip, $startPort, $endPort, false);
    }

    public function addIpSegmentAllowPort(string $segment, int|string $startPort, int|string|null $endPort = null): self
    {
        return $this->addSegmentRule($segment, $startPort, $endPort, true);
    }

    public function addIpSegmentBlockPort(string $segment, int|string $startPort, int|string|null $endPort = null): self
    {
        return $this->addSegmentRule($segment, $startPort, $endPort, false);
    }

    public function isAllowAccess(string $ip, int|string $port): bool
    {
        $normalizedIp = IpAddress::pack($ip);
        $normalizedPort = PortRange::normalizePort($port);
        $ipKey = IpAddress::key($normalizedIp);

        // 精确 IP+端口规则优先于网段规则，可用于设置更精确的放行或封禁例外。
        if ($this->portMatches($normalizedPort, $this->ipAllowRules[$ipKey] ?? [])) {
            return true;
        }
        if ($this->portMatches($normalizedPort, $this->ipBlockRules[$ipKey] ?? [])) {
            return false;
        }
        if ($this->matchesSegmentIndex($normalizedIp, $normalizedPort, $this->segmentAllowIndex)) {
            return true;
        }
        if ($this->matchesSegmentIndex($normalizedIp, $normalizedPort, $this->segmentBlockIndex)) {
            return false;
        }

        // 当前 IP 和端口没有命中任何规则时默认放行。
        return true;
    }

    /** 仅同一个 IP 下，放行与封禁的端口范围发生重叠时才算冲突。 */
    private function addIpRule(
        string $ip,
        int|string $startPort,
        int|string|null $endPort,
        bool $allow
    ): self {
        $normalizedIp = IpAddress::pack($ip);
        $range = PortRange::from($startPort, $endPort);
        $key = IpAddress::key($normalizedIp);
        $oppositeRules = $allow ? $this->ipBlockRules : $this->ipAllowRules;

        // 精确 IP 可与相反类型的网段规则共存，因此这里只检查精确 IP 规则。
        foreach ($oppositeRules[$key] ?? [] as $existingRange) {
            if ($range->overlaps($existingRange)) {
                throw new LogicException(sprintf(
                    'Rule "%s:%s" conflicts with existing rule "%s:%s" in the IP %s list.',
                    $ip,
                    $range->format(),
                    IpAddress::format($normalizedIp),
                    $existingRange->format(),
                    $allow ? 'block' : 'allow'
                ));
            }
        }

        if ($allow) {
            $this->ipAllowRules[$key] = $this->mergePortRanges($this->ipAllowRules[$key] ?? [], $range);
        } else {
            $this->ipBlockRules[$key] = $this->mergePortRanges($this->ipBlockRules[$key] ?? [], $range);
        }

        return $this;
    }

    private function addSegmentRule(
        string $segment,
        int|string $startPort,
        int|string|null $endPort,
        bool $allow
    ): self {
        $network = IpNetwork::fromCidr($segment);
        $range = PortRange::from($startPort, $endPort);
        $oppositeRules = $allow ? $this->segmentBlockRules : $this->segmentAllowRules;

        // 只有地址范围和端口范围同时重叠，两个网段规则才真正冲突。
        foreach ($oppositeRules as $existingRule) {
            if ($network->overlaps($existingRule['network']) && $range->overlaps($existingRule['ports'])) {
                throw new LogicException(sprintf(
                    'Rule "%s:%s" conflicts with existing rule "%s:%s" in the segment %s list.',
                    $segment,
                    $range->format(),
                    $existingRule['network']->format(),
                    $existingRule['ports']->format(),
                    $allow ? 'block' : 'allow'
                ));
            }
        }

        $rule = ['network' => $network, 'ports' => $range];
        if ($allow) {
            $this->segmentAllowRules[] = $rule;
            $this->indexSegmentRule($this->segmentAllowIndex, $network, $range);
        } else {
            $this->segmentBlockRules[] = $rule;
            $this->indexSegmentRule($this->segmentBlockIndex, $network, $range);
        }

        return $this;
    }

    /** @param array<int, PortRange> $ranges */
    private function portMatches(int $port, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if ($range->contains($port)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 将相同类型中重叠或相邻的端口闭区间合并，减少检测时的遍历次数。
     *
     * @param array<int, PortRange> $ranges
     * @return array<int, PortRange>
     */
    private function mergePortRanges(array $ranges, PortRange $candidate): array
    {
        $ranges[] = $candidate;
        usort($ranges, static fn (PortRange $first, PortRange $second): int => $first->start() <=> $second->start());

        $merged = [];
        foreach ($ranges as $range) {
            $lastIndex = count($merged) - 1;
            if ($lastIndex >= 0 && $merged[$lastIndex]->canMerge($range)) {
                $merged[$lastIndex] = $merged[$lastIndex]->merge($range);
            } else {
                $merged[] = $range;
            }
        }

        return $merged;
    }

    /** @param array<int, array<int, array<string, array<int, PortRange>>>> $index */
    private function indexSegmentRule(array &$index, IpNetwork $network, PortRange $range): void
    {
        $bytes = $network->addressBytes();
        $prefix = $network->prefixLength();
        $key = $network->networkKey();
        $index[$bytes][$prefix][$key] = $this->mergePortRanges($index[$bytes][$prefix][$key] ?? [], $range);
    }

    /**
     * 每个已使用前缀只计算一次网络地址，再检查该网段下已经合并的端口区间。
     *
     * @param array<int, array<int, array<string, array<int, PortRange>>>> $index
     */
    private function matchesSegmentIndex(string $packedIp, int $port, array $index): bool
    {
        foreach ($index[strlen($packedIp)] ?? [] as $prefix => $networks) {
            $networkKey = IpNetwork::networkKeyFor($packedIp, $prefix);
            if (isset($networks[$networkKey]) && $this->portMatches($port, $networks[$networkKey])) {
                return true;
            }
        }

        return false;
    }
}
