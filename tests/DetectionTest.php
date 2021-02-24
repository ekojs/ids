<?php
/**
 * Intrusion Detection System
 * Created by Eko Junaidi Salam <eko.junaidi.salam@gmail.com>
 * 
 * Filter based on PHPIDS with some modification
 * License : LGPL v3.0
 */

declare(strict_types=1);
use PHPUnit\Framework\TestCase;

final class DetectionTest extends TestCase
{
    public function testInstanceIps(): void {
        $this->assertInstanceOf(
            Ips::class,
            Ips::getInstance()
        );
    }

    public function testNullString(): void {
        $ips = Ips::getInstance();
        $this->expectError();
        $ips->detect(null);
    }

    public function testNormalString(): void {
        $ips = Ips::getInstance();
        $this->assertFalse($ips->detect("hallo bro"));
    }

    public function testSqliBase64Injection(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("LTQ3MTQnIFVOSU9OIEFMTCBTRUxFQ1QgTlVMTCxOVUxMLE5VTEwsKFNFTEVDVCBDT05DQVQoMHg3MTc2NzE3YTcxLElGTlVMTChDQVNUKG5hbWFfdGFiZWwgQVMgQ0hBUiksMHgyMCksMHg2ZTcwNzk3MDY5NmQsSUZOVUxMKENBU1QobmFtYV9rb2xvbSBBUyBDSEFSKSwweDIwKSwweDZlNzA3OTcwNjk2ZCxJRk5VTEwoQ0FTVChuYW1hX2tvbG9tIEFTIENIQVIpLDB4MjApLDB4NmU3MDc5NzA2OTZkLElGTlVMTChDQVNUKG5hbWFfa29sb20gQVMgQ0hBUiksMHgyMCksMHg2ZTcwNzk3MDY5NmQsSUZOVUxMKENBU1QobmFtYV9rb2xvbSBBUyBDSEFSKSwweDIwKSwweDcxNzY3MDc2NzEpIEZST00gbmFtYV90YWJlbCBMSU1JVCAyODMyOCwxKSxOVUxMLE5VTEwsTlVMTCxOVUxMLE5VTEwsTlVMTC0tIC03",'b64');
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliAuthenticationBypass1(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("' or 1=1 limit 1 -- -+");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliAuthenticationBypass2(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect('1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055');
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliAuthenticationBypass3(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("admin') or ('1'='1'/*");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliRoutedInjection(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliPolygotInjection(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("SUYoU1VCU1RSKEBAdmVyc2lvbiwxLDEpPDUsQkVOQ0hNQVJLKDIwMDAwMDAsU0hBMSgweERFN0VDNzFGMSkpLFNMRUVQKDEpKS8qJ1hPUihJRihTVUJTVFIoQEB2ZXJzaW9uLDEsMSk8NSxCRU5DSE1BUksoMjAwMDAwMCxTSEExKDB4REU3RUM3MUYxKSksU0xFRVAoMSkpKU9SJ3wiWE9SKElGKFNVQlNUUihAQHZlcnNpb24sMSwxKTw1LEJFTkNITUFSSygyMDAwMDAwLFNIQTEoMHhERTdFQzcxRjEpKSxTTEVFUCgxKSkpT1IiKi8=",'b64');
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliBaypassWaf(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("?id=1%A0and%A01=1%A0--");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testSqliBaypassUsingWhitespace(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("?id=1/*comment*/and/**/1=1/**/--");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testXssRepetitiveAttacks(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("<script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script><script>alert(1)</script>");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testLongDirectoryTraversalAndLocalFile(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00../../../etc/passwd%00");
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testFloodLogAttack(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("ZXhhbXBsZS5waHA/PD9ldmFsKGFycmF5X3BvcCgkX0dFVCkpPz49PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",'b64');
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }

    public function testBypassRegex(): void {
        $ips = Ips::getInstance();
        $impact = $ips->detect("L1BsZWFzZSBzdWJtaXQgdGhlIHN0cmluZ1wKICAgICAgICB0byBoZWxwIHVzIG1ha2UgdGhlIFwKICAgICAgICBQSFBJRFMgYmV0dGVyLi8seT0oJ2FsZXJcCiAgICAgICAgdCcpLHg9dGhpcyx4PXhbeV0KICAgICAgICB4KCdJIGNhbnQgbGV0IHlvdSBoYXZlIGFsbCB0aGUgZnVuIHRob3JubWFrZXInKSwvYWJjIGFiY1wKICAgICAgICBhYmMgYWJjIGFiY1wKICAgICAgICBhYmNcCiAgICAgICAgLywvYWJjIGFiY1wKICAgICAgICBhYmMgYWJjIGFiY1wKICAgICAgICBhYmNcCiAgICAgICAgLw==",'b64');
        // echo var_export($impact);
        $this->assertIsArray($impact);
    }
}