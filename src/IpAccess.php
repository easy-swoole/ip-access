<?php

declare(strict_types=1);

namespace EasySwoole\IpAccess;

use InvalidArgumentException;
use LogicException;

final class IpAccess
{
    /** @var array<string, true> */
    private array $whiteIps = [];
    /** @var array<string, true> */
    private array $blackIps = [];
    /** @var array<string, array{network: string, prefix: int, bytes: int}> */
    private array $whiteSegments = [];
    /** @var array<string, array{network: string, prefix: int, bytes: int}> */
    private array $blackSegments = [];

    public function addWhiteIp(string $ip): self
    {
        $key = bin2hex($this->normalizeIp($ip));
        if (isset($this->blackIps[$key])) {
            throw new LogicException(sprintf('IP "%s" already exists in the blacklist.', $ip));
        }
        $this->whiteIps[$key] = true;
        return $this;
    }

    public function addBlackIp(string $ip): self
    {
        $key = bin2hex($this->normalizeIp($ip));
        if (isset($this->whiteIps[$key])) {
            throw new LogicException(sprintf('IP "%s" already exists in the whitelist.', $ip));
        }
        $this->blackIps[$key] = true;
        return $this;
    }

    public function addWhiteIpSegment(string $segment): self
    {
        $parsed = $this->parseSegment($segment);
        $this->assertNoSegmentConflict($segment, $parsed, $this->blackSegments, 'blacklist');
        $this->whiteSegments[$this->segmentKey($parsed)] = $parsed;
        return $this;
    }

    public function addBlackIpSegment(string $segment): self
    {
        $parsed = $this->parseSegment($segment);
        $this->assertNoSegmentConflict($segment, $parsed, $this->whiteSegments, 'whitelist');
        $this->blackSegments[$this->segmentKey($parsed)] = $parsed;
        return $this;
    }

    public function isAllowAccess(string $ip): bool
    {
        $normalized = $this->normalizeIp($ip);
        $key = bin2hex($normalized);
        if (isset($this->whiteIps[$key])) {
            return true;
        }
        if (isset($this->blackIps[$key])) {
            return false;
        }
        foreach ($this->whiteSegments as $segment) {
            if ($this->isInSegment($normalized, $segment)) {
                return true;
            }
        }
        foreach ($this->blackSegments as $segment) {
            if ($this->isInSegment($normalized, $segment)) {
                return false;
            }
        }
        return true;
    }

    private function normalizeIp(string $ip): string
    {
        $packed = @inet_pton(trim($ip));
        if ($packed === false) {
            throw new InvalidArgumentException(sprintf('Invalid IP address: "%s".', $ip));
        }
        return $packed;
    }

    /** @return array{network: string, prefix: int, bytes: int} */
    private function parseSegment(string $segment): array
    {
        $parts = explode('/', trim($segment));
        if (count($parts) !== 2 || $parts[1] === '' || !ctype_digit($parts[1])) {
            throw new InvalidArgumentException(sprintf('Invalid CIDR segment: "%s".', $segment));
        }
        $ip = $this->normalizeIp($parts[0]);
        $bytes = strlen($ip);
        $prefix = (int) $parts[1];
        $maxPrefix = $bytes * 8;
        if ($prefix > $maxPrefix) {
            throw new InvalidArgumentException(sprintf('Invalid prefix length in "%s"; expected 0-%d.', $segment, $maxPrefix));
        }
        return ['network' => $this->applyMask($ip, $prefix), 'prefix' => $prefix, 'bytes' => $bytes];
    }

    /**
     * @param array{network: string, prefix: int, bytes: int} $candidate
     * @param array<string, array{network: string, prefix: int, bytes: int}> $oppositeSegments
     */
    private function assertNoSegmentConflict(string $input, array $candidate, array $oppositeSegments, string $oppositeList): void
    {
        foreach ($oppositeSegments as $segment) {
            if ($candidate['bytes'] !== $segment['bytes']) {
                continue;
            }
            $commonPrefix = min($candidate['prefix'], $segment['prefix']);
            if ($this->applyMask($candidate['network'], $commonPrefix) === $this->applyMask($segment['network'], $commonPrefix)) {
                throw new LogicException(sprintf(
                    'Segment "%s" overlaps existing segment "%s" in the %s.',
                    $input,
                    $this->formatSegment($segment),
                    $oppositeList
                ));
            }
        }
    }

    /** @param array{network: string, prefix: int, bytes: int} $segment */
    private function isInSegment(string $ip, array $segment): bool
    {
        return strlen($ip) === $segment['bytes'] && $this->applyMask($ip, $segment['prefix']) === $segment['network'];
    }

    private function applyMask(string $ip, int $prefix): string
    {
        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;
        $masked = substr($ip, 0, $fullBytes);
        if ($remainingBits > 0) {
            $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
            $masked .= chr(ord($ip[$fullBytes]) & $mask);
            ++$fullBytes;
        }
        return str_pad($masked, strlen($ip), "\0");
    }

    /** @param array{network: string, prefix: int, bytes: int} $segment */
    private function segmentKey(array $segment): string
    {
        return $segment['bytes'] . ':' . bin2hex($segment['network']) . '/' . $segment['prefix'];
    }

    /** @param array{network: string, prefix: int, bytes: int} $segment */
    private function formatSegment(array $segment): string
    {
        return inet_ntop($segment['network']) . '/' . $segment['prefix'];
    }
}
