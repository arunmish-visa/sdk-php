<?php
namespace net\authorize\util;

/**
 * Unit tests for Log masking functionality.
 * Tests XML masking, JSON masking, credit card masking, multi-occurrence,
 * multi-line, and PCRE failure scenarios.
 *
 * @package    AuthorizeNet
 * @subpackage net\authorize\util
 */
class LogMaskingTest extends \PHPUnit\Framework\TestCase
{
    private $log;
    private $logFile;

    protected function setUp(): void
    {
        $this->logFile = tempnam(sys_get_temp_dir(), 'anet_log_test_');
        $this->log = new Log();
        $this->log->setLogFile($this->logFile);
        $this->log->setLogLevel(ANET_LOG_DEBUG);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->logFile)) {
            unlink($this->logFile);
        }
    }

    private function getLogContent(): string
    {
        return file_get_contents($this->logFile);
    }

    // === JSON Masking Tests ===

    public function testMaskJsonCardNumber()
    {
        $json = '{"cardNumber":"4111111111111111","amount":"10.00"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringContainsString('"cardNumber"', $content);
        $this->assertStringContainsString('10.00', $content);
    }

    public function testMaskJsonCardCode()
    {
        $json = '{"cardCode":"123","cardNumber":"4111111111111111"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('"123"', $content);
        $this->assertStringContainsString('"cardCode":"xxxx"', $content);
    }

    public function testMaskJsonTransactionKey()
    {
        $json = '{"transactionKey":"secretkey123","name":"testmerchant"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('secretkey123', $content);
        $this->assertStringContainsString('"transactionKey":"xxxx"', $content);
    }

    public function testMaskJsonExpirationDate()
    {
        $json = '{"expirationDate":"2025-12","cardNumber":"4111111111111111"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('2025-12', $content);
        $this->assertStringContainsString('"expirationDate":"xxxx"', $content);
    }

    public function testMaskJsonAccountNumber()
    {
        $json = '{"accountNumber":"1234567890123456","routingNumber":"021000021"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('1234567890123456', $content);
        $this->assertStringContainsString('"accountNumber"', $content);
    }

    public function testMaskJsonMultipleOccurrences()
    {
        $json = '{"items":[{"cardNumber":"4111111111111111"},{"cardNumber":"5500000000000004"}]}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringNotContainsString('5500000000000004', $content);
    }

    public function testMaskJsonWithSpacesAroundColon()
    {
        $json = '{"cardNumber" : "4111111111111111"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
    }

    // === XML Masking Tests ===

    public function testMaskXmlCardNumber()
    {
        $xml = '<cardNumber>4111111111111111</cardNumber>';
        $this->log->info($xml);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringContainsString('<cardNumber>', $content);
    }

    public function testMaskXmlMultipleOccurrences()
    {
        $xml = '<root><cardNumber>4111111111111111</cardNumber><other>data</other><cardNumber>5500000000000004</cardNumber></root>';
        $this->log->info($xml);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringNotContainsString('5500000000000004', $content);
        $this->assertStringContainsString('data', $content);
    }

    public function testMaskXmlMultiLine()
    {
        $xml = "<transactionKey>\nsecretkey123\n</transactionKey>";
        $this->log->info($xml);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('secretkey123', $content);
    }

    public function testMaskXmlTransactionKey()
    {
        $xml = '<transactionKey>mysecretkey</transactionKey>';
        $this->log->info($xml);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('mysecretkey', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    // === Credit Card Regex Masking Tests ===

    public function testMaskCreditCardVisaInFreeText()
    {
        $text = 'Payment received with card 4111111111111111 for order 12345';
        $this->log->info($text);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringContainsString('order 12345', $content);
    }

    public function testMaskCreditCardMastercardInFreeText()
    {
        $text = 'Card used: 5500000000000004';
        $this->log->info($text);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('5500000000000004', $content);
    }

    public function testMaskCreditCardWithDashes()
    {
        $text = 'Card: 4111-1111-1111-1111';
        $this->log->info($text);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111-1111-1111-1111', $content);
    }

    // === PCRE Failure / Edge Case Tests ===

    public function testNonSensitiveDataPreserved()
    {
        $text = 'Transaction completed successfully for merchant ABC, amount $25.00';
        $this->log->info($text);
        $content = $this->getLogContent();

        $this->assertStringContainsString('Transaction completed successfully', $content);
        $this->assertStringContainsString('merchant ABC', $content);
        $this->assertStringContainsString('$25.00', $content);
    }

    public function testEmptyStringDoesNotCrash()
    {
        $this->log->info('');
        $content = $this->getLogContent();
        // Should not throw, log file should exist
        $this->assertNotFalse($content);
    }

    public function testMaskJsonNameOnAccount()
    {
        $json = '{"nameOnAccount":"John Doe","routingNumber":"021000021"}';
        $this->log->info($json);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('John Doe', $content);
        $this->assertStringContainsString('"nameOnAccount":"xxxx"', $content);
    }

    // === Combined Format Tests ===

    public function testMaskMixedJsonAndCreditCard()
    {
        // JSON payload with a credit card also appearing in freetext after
        $mixed = '{"cardNumber":"4111111111111111"} processed card 5500000000000004';
        $this->log->info($mixed);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringNotContainsString('5500000000000004', $content);
    }
}
