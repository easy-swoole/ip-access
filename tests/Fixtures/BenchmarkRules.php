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
    public const SEGMENT_IP = '10.0.255.42';
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
}
