<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Tests\Fixtures;

use EasySwoole\IpAccess\IpAccess;
use EasySwoole\IpAccess\IpPortAccess;

/**
 * 基准测试使用的固定规则集。
 *
 * 规则准备过程不计入检测耗时；网段场景按顺序创建 256 个 /24 网段，
 * 检测目标位于最后添加的网段，用于验证规则数量增加后的索引查询效率。
 */
final class BenchmarkRules
{
    public const EXACT_IP = '192.168.1.100';
    public const SEGMENT_IP = '10.0.255.173';
    public const LARGE_SEGMENT_IP = '10.15.255.219';
    public const PORT = 443;

    private function __construct()
    {
    }

    public static function ipAccessWithExactRule(): IpAccess
    {
        $access = new IpAccess();
        $access->addBlackIp(self::EXACT_IP);

        return $access;
    }

    public static function ipAccessWithSegments(): IpAccess
    {
        $access = new IpAccess();
        for ($i = 0; $i < 256; ++$i) {
            $access->addBlackIpSegment(sprintf('10.0.%d.0/24', $i));
        }

        return $access;
    }

    public static function ipPortAccessWithExactRule(): IpPortAccess
    {
        $access = new IpPortAccess();
        $access->addIpBlockPort(self::EXACT_IP, self::PORT);

        return $access;
    }

    public static function ipPortAccessWithSegments(): IpPortAccess
    {
        $access = new IpPortAccess();
        for ($i = 0; $i < 256; ++$i) {
            $access->addIpSegmentBlockPort(sprintf('10.0.%d.0/24', $i), self::PORT);
        }

        return $access;
    }

    /** 创建 4,096 条连续的 /24 规则：10.0.0.0/24 至 10.15.255.0/24。 */
    public static function ipAccessWithLargeSegments(): IpAccess
    {
        $access = new IpAccess();
        foreach (self::largeSegments() as $segment) {
            $access->addBlackIpSegment($segment);
        }

        return $access;
    }

    public static function ipPortAccessWithLargeSegments(): IpPortAccess
    {
        $access = new IpPortAccess();
        foreach (self::largeSegments() as $segment) {
            $access->addIpSegmentBlockPort($segment, self::PORT);
        }

        return $access;
    }

    /**
     * 使用固定种子的确定性伪随机序列创建 1,024 条不重复网段规则。
     *
     * @return array{access: IpAccess, target: string}
     */
    public static function ipAccessWithRandomSegments(): array
    {
        $data = self::randomSegments();
        $access = new IpAccess();
        foreach ($data['segments'] as $segment) {
            $access->addBlackIpSegment($segment);
        }

        return ['access' => $access, 'target' => $data['target']];
    }

    /** @return array{access: IpPortAccess, target: string} */
    public static function ipPortAccessWithRandomSegments(): array
    {
        $data = self::randomSegments();
        $access = new IpPortAccess();
        foreach ($data['segments'] as $segment) {
            $access->addIpSegmentBlockPort($segment, self::PORT);
        }

        return ['access' => $access, 'target' => $data['target']];
    }

    /** @return array<int, string> */
    private static function largeSegments(): array
    {
        $segments = [];
        for ($secondOctet = 0; $secondOctet < 16; ++$secondOctet) {
            for ($thirdOctet = 0; $thirdOctet < 256; ++$thirdOctet) {
                $segments[] = sprintf('10.%d.%d.0/24', $secondOctet, $thirdOctet);
            }
        }

        return $segments;
    }

    /** @return array{segments: array<int, string>, target: string} */
    private static function randomSegments(): array
    {
        $state = 0x12345678;
        $segments = [];
        $target = '';

        while (count($segments) < 1_024) {
            // 本地 LCG 不修改 PHP 全局随机数状态，且在相同 PHP 整数平台上结果可复现。
            $state = (1103515245 * $state + 12345) & 0x7FFFFFFF;
            $prefix = 16 + ($state % 13);
            $address = 0x0A000000 | ($state & 0x00FFFFFF);
            $mask = (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
            $network = $address & $mask;
            $key = $network . '/' . $prefix;

            if (isset($segments[$key])) {
                continue;
            }

            $segments[$key] = long2ip($network) . '/' . $prefix;

            // 使用另一组确定性计算，从当前网段的可用主机范围内选择随机目标 IP。
            $hostMask = (1 << (32 - $prefix)) - 1;
            $hostState = (1664525 * $state + 1013904223) & 0x7FFFFFFF;
            $hostOffset = 1 + ($hostState % ($hostMask - 1));
            $target = long2ip($network + $hostOffset);
        }

        return ['segments' => array_values($segments), 'target' => $target];
    }
}
