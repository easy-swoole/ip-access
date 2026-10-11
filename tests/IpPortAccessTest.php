<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Tests;

use EasySwoole\IpAccess\IpPortAccess;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

final class IpPortAccessTest extends TestCase
{
    public function testIpSinglePortAndRangeRules(): void
    {
        $access = new IpPortAccess();
        $access->addIpBlockPort('192.168.0.1', '80')
            ->addIpBlockPort('192.168.0.1', '1000', '2000');

        self::assertFalse($access->isAllowAccess('192.168.0.1', '80'));
        self::assertFalse($access->isAllowAccess('192.168.0.1', 1500));
        self::assertTrue($access->isAllowAccess('192.168.0.1', 443));
        self::assertTrue($access->isAllowAccess('192.168.0.2', 80));
    }

    public function testExactIpRuleOverridesSegmentRule(): void
    {
        $access = new IpPortAccess();
        $access->addIpSegmentBlockPort('192.168.1.0/24', 8000, 9000)
            ->addIpAllowPort('192.168.1.31', 8080);

        self::assertTrue($access->isAllowAccess('192.168.1.31', 8080));
        self::assertFalse($access->isAllowAccess('192.168.1.31', 8081));
        self::assertFalse($access->isAllowAccess('192.168.1.32', 8080));
    }

    public function testOverlappingIpPortRulesConflict(): void
    {
        $access = new IpPortAccess();
        $access->addIpAllowPort('127.0.0.1', 8000, 9000);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Rule "127.0.0.1:8500-9500" conflicts with existing rule "127.0.0.1:8000-9000" in the IP allow list.'
        );
        $access->addIpBlockPort('127.0.0.1', 8500, 9500);
    }

    public function testNonOverlappingPortsDoNotConflict(): void
    {
        $access = new IpPortAccess();
        $access->addIpAllowPort('127.0.0.1', 80)
            ->addIpBlockPort('127.0.0.1', 443);

        self::assertTrue($access->isAllowAccess('127.0.0.1', 80));
        self::assertFalse($access->isAllowAccess('127.0.0.1', 443));
    }

    public function testOverlappingSegmentAndPortRulesConflict(): void
    {
        $access = new IpPortAccess();
        $access->addIpSegmentBlockPort('10.0.0.0/8', 80, 100);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Rule "10.1.0.0/16:90" conflicts with existing rule "10.0.0.0/8:80-100" in the segment block list.'
        );
        $access->addIpSegmentAllowPort('10.1.0.0/16', 90);
    }

    public function testOverlappingSegmentsWithDifferentPortsDoNotConflict(): void
    {
        $access = new IpPortAccess();
        $access->addIpSegmentAllowPort('10.0.0.0/8', 80)
            ->addIpSegmentBlockPort('10.1.0.0/16', 443);

        self::assertTrue($access->isAllowAccess('10.1.2.3', 80));
        self::assertFalse($access->isAllowAccess('10.1.2.3', 443));
    }

    public function testIpv6RulesAreSupported(): void
    {
        $access = new IpPortAccess();
        $access->addIpSegmentBlockPort('2001:db8::1234/64', 443)
            ->addIpAllowPort('2001:db8::1', 443);

        self::assertTrue($access->isAllowAccess('2001:0db8::1', 443));
        self::assertFalse($access->isAllowAccess('2001:db8::2', 443));
    }

    /** @dataProvider invalidPortProvider */
    public function testInvalidPortsAreRejected(int|string $start, int|string|null $end): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new IpPortAccess())->addIpAllowPort('127.0.0.1', $start, $end);
    }

    /** @return array<string, array{int|string, int|string|null}> */
    public function invalidPortProvider(): array
    {
        return [
            'zero' => [0, null],
            'too large' => [65536, null],
            'not numeric' => ['http', null],
            'reversed range' => [9000, 8000],
        ];
    }
}
