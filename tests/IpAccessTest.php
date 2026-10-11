<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess\Tests;

use EasySwoole\IpAccess\IpAccess;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

final class IpAccessTest extends TestCase
{
    public function testBlackSegmentWithExactWhiteException(): void
    {
        $access = new IpAccess();
        $access->addBlackIpSegment('192.168.1.0/24')->addWhiteIp('192.168.1.31');
        self::assertTrue($access->isAllowAccess('192.168.1.31'));
        self::assertFalse($access->isAllowAccess('192.168.1.32'));
        self::assertTrue($access->isAllowAccess('10.0.0.1'));
    }

    public function testExactIpCannotExistInBothLists(): void
    {
        $access = new IpAccess();
        $access->addWhiteIp('127.0.0.1');
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'IP "127.0.0.1" conflicts with existing IP "127.0.0.1" in the whitelist.'
        );
        $access->addBlackIp('127.0.0.1');
    }

    public function testIpConflictMessageUsesCanonicalExistingIp(): void
    {
        $access = new IpAccess();
        $access->addBlackIp('2001:db8::1');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'IP "2001:0db8:0:0:0:0:0:1" conflicts with existing IP "2001:db8::1" in the blacklist.'
        );
        $access->addWhiteIp('2001:0db8:0:0:0:0:0:1');
    }

    public function testOverlappingSegmentsCannotExistInOppositeLists(): void
    {
        $access = new IpAccess();
        $access->addWhiteIpSegment('192.168.1.0/24');
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Segment "192.168.1.128/25" overlaps existing segment "192.168.1.0/24" in the whitelist.'
        );
        $access->addBlackIpSegment('192.168.1.128/25');
    }

    public function testConflictMessageUsesCanonicalExistingSegment(): void
    {
        $access = new IpAccess();
        $access->addBlackIpSegment('2001:db8::1234/64');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Segment "2001:db8::abcd/80" overlaps existing segment "2001:db8::/64" in the blacklist.'
        );
        $access->addWhiteIpSegment('2001:db8::abcd/80');
    }

    public function testExactBlackIpOverridesWhiteSegment(): void
    {
        $access = new IpAccess();
        $access->addWhiteIpSegment('10.0.0.0/8')->addBlackIp('10.0.0.7');
        self::assertFalse($access->isAllowAccess('10.0.0.7'));
        self::assertTrue($access->isAllowAccess('10.0.0.8'));
    }

    public function testIpv6AndNonCanonicalNetworkAddressAreSupported(): void
    {
        $access = new IpAccess();
        $access->addBlackIpSegment('2001:db8::1234/64')->addWhiteIp('2001:db8::1');
        self::assertTrue($access->isAllowAccess('2001:0db8:0:0:0:0:0:1'));
        self::assertFalse($access->isAllowAccess('2001:db8::2'));
    }

    public function testInvalidAddressIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new IpAccess())->addWhiteIp('not-an-ip');
    }

    public function testInvalidPrefixIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new IpAccess())->addBlackIpSegment('192.168.1.0/33');
    }
}
