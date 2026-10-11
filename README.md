# ip-access

一个支持 IPv4、IPv6、CIDR 网段及端口范围的 PHP IP 访问控制组件。

要求 PHP 8.1 或更高版本。

## 安装

```bash
composer require easyswoole/ip-access
```

## IpAccess：IP 黑白名单

`IpAccess` 仅根据 IP 地址判断是否允许访问。

```php
<?php

use EasySwoole\IpAccess\IpAccess;

$access = new IpAccess();

// 添加单个白名单 IP
$access->addWhiteIp('127.0.0.1');

// 添加白名单网段
$access->addWhiteIpSegment('172.16.0.0/16');

// 添加单个黑名单 IP
$access->addBlackIp('192.168.0.1');

// 添加黑名单网段
$access->addBlackIpSegment('192.168.1.0/24');

// 黑名单网段中的单个白名单例外
$access->addWhiteIp('192.168.1.31');

$access->isAllowAccess('127.0.0.1');    // true
$access->isAllowAccess('192.168.0.1');  // false
$access->isAllowAccess('192.168.1.31'); // true
$access->isAllowAccess('192.168.1.32'); // false
$access->isAllowAccess('10.0.0.1');     // true，未命中规则时默认放行
```

所有 `add*` 方法都会返回当前对象，因此可以链式调用：

```php
$access
    ->addBlackIpSegment('10.0.0.0/8')
    ->addWhiteIp('10.0.0.10');
```

### IpAccess 优先级

判断顺序由高到低如下：

1. 单个白名单 IP
2. 单个黑名单 IP
3. 白名单网段
4. 黑名单网段
5. 未命中任何规则时默认放行

单个 IP 规则比网段规则更精确，因此优先级更高。例如，可以通过单个白名单 IP 放行黑名单网段中的某个地址；也可以通过单个黑名单 IP，封禁白名单网段中的某个地址。

### IpAccess 冲突规则

- 同一个 IP 不能同时存在于单个 IP 白名单和黑名单中。
- 白名单网段和黑名单网段的地址范围不能重叠。比如已有白名单 `192.168.1.0/24` 时，不能添加黑名单 `192.168.1.128/25`。
- 同一类型的规则可以重复添加；相同名单中的网段允许重叠。
- 单个 IP 与相反类型的网段允许重叠，用于设置精确例外。
- 发生冲突时抛出 `LogicException`，异常信息会包含本次添加的规则和已有的冲突规则。
- IP 或 CIDR 格式非法时抛出 `InvalidArgumentException`。

## IpPortAccess：IP 端口访问规则

`IpPortAccess` 根据 IP 地址和端口共同判断是否允许访问。端口既可以使用整数，也可以使用仅包含数字的字符串。

```php
<?php

use EasySwoole\IpAccess\IpPortAccess;

$access = new IpPortAccess();

// 单个 IP + 单端口
$access->addIpAllowPort('127.0.0.1', '80');
$access->addIpBlockPort('192.168.0.1', '443');

// 单个 IP + 端口闭区间（包含起止端口）
$access->addIpAllowPort('127.0.0.1', '8000', '9000');
$access->addIpBlockPort('192.168.0.1', '1000', '2000');

// 网段 + 单端口
$access->addIpSegmentAllowPort('172.16.0.0/16', '80');
$access->addIpSegmentBlockPort('192.168.1.0/24', '443');

// 网段 + 端口闭区间
$access->addIpSegmentAllowPort('172.17.0.0/16', '8000', '9000');
$access->addIpSegmentBlockPort('192.168.2.0/24', '1000', '2000');

$access->isAllowAccess('127.0.0.1', '80');     // true
$access->isAllowAccess('192.168.0.1', '443'); // false
$access->isAllowAccess('10.0.0.1', '80');     // true，未命中规则时默认放行
```

也可以在被封禁的网段和端口范围中添加精确 IP+端口例外：

```php
$access = new IpPortAccess();

$access
    ->addIpSegmentBlockPort('192.168.1.0/24', 8000, 9000)
    ->addIpAllowPort('192.168.1.31', 8080);

$access->isAllowAccess('192.168.1.31', 8080); // true，命中精确放行规则
$access->isAllowAccess('192.168.1.31', 8081); // false，回退并命中网段封禁规则
$access->isAllowAccess('192.168.1.32', 8080); // false
```

### IpPortAccess 优先级

判断顺序由高到低如下：

1. 单个 IP 的放行端口规则
2. 单个 IP 的封禁端口规则
3. IP 网段的放行端口规则
4. IP 网段的封禁端口规则
5. 未命中任何规则时默认放行

只有 IP 和端口同时命中规则，该规则才生效。某个 IP 存在精确规则，并不意味着它的所有端口都会停止匹配网段规则；如果当前端口没有命中精确规则，会继续检查网段规则。

### IpPortAccess 冲突规则

- 对于同一个精确 IP，放行和封禁端口范围不能重叠。
- 对于网段规则，只有“IP 地址范围重叠”且“端口范围也重叠”时才构成冲突。
- 网段地址范围重叠但端口范围不重叠时，可以同时添加。
- 相同类型的规则允许重叠或重复添加。
- 精确 IP+端口规则与相反类型的网段+端口规则允许重叠，用于设置精确例外。
- 端口范围是闭区间，端口必须在 `1` 到 `65535` 之间，且起始端口不能大于结束端口。
- 发生冲突时抛出 `LogicException`，异常信息会包含本次添加的规则和已有的冲突规则。
- IP、CIDR 或端口格式非法时抛出 `InvalidArgumentException`。

例如，以下规则会发生冲突：

```php
$access = new IpPortAccess();
$access->addIpSegmentBlockPort('10.0.0.0/8', 80, 100);

// IP 范围和端口范围均有重叠，抛出 LogicException
$access->addIpSegmentAllowPort('10.1.0.0/16', 90);
```

异常信息类似：

```text
Rule "10.1.0.0/16:90" conflicts with existing rule "10.0.0.0/8:80-100" in the segment block list.
```

以下规则不会冲突，因为端口不同：

```php
$access = new IpPortAccess();
$access
    ->addIpSegmentAllowPort('10.0.0.0/8', 80)
    ->addIpSegmentBlockPort('10.1.0.0/16', 443);
```
