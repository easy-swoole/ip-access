<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Tests;

use EasySwoole\IpAccess\Tests\Fixtures\BenchmarkRules;
use PHPUnit\Framework\TestCase;

final class BenchmarkRulesTest extends TestCase
{
    public function testExactBenchmarkRulesBlockTargetOnly(): void
    {
        $ipAccess = BenchmarkRules::ipAccessWithExactRule();
        $portAccess = BenchmarkRules::ipPortAccessWithExactRule();

        self::assertFalse($ipAccess->isAllowAccess(BenchmarkRules::EXACT_IP));
        self::assertTrue($ipAccess->isAllowAccess('192.168.1.101'));
        self::assertFalse($portAccess->isAllowAccess(BenchmarkRules::EXACT_IP, BenchmarkRules::PORT));
        self::assertTrue($portAccess->isAllowAccess(BenchmarkRules::EXACT_IP, 80));
    }

    public function testSegmentBenchmarkRulesHitLastSegment(): void
    {
        $ipAccess = BenchmarkRules::ipAccessWithSegments();
        $portAccess = BenchmarkRules::ipPortAccessWithSegments();

        self::assertFalse($ipAccess->isAllowAccess(BenchmarkRules::SEGMENT_IP));
        self::assertTrue($ipAccess->isAllowAccess('10.1.0.1'));
        self::assertFalse($portAccess->isAllowAccess(BenchmarkRules::SEGMENT_IP, BenchmarkRules::PORT));
        self::assertTrue($portAccess->isAllowAccess(BenchmarkRules::SEGMENT_IP, 80));
    }
}
