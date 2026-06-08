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

    // === Object-Reflection Masking Path Tests (maskSensitiveProperties) ===

    public function testMaskObjectPassword()
    {
        $obj = new \stdClass();
        $obj->password = 'secretPass123';
        $obj->name = 'testMerchant';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('secretPass123', $content);
        $this->assertStringContainsString('xxxx', $content);
        $this->assertStringContainsString('testMerchant', $content);
    }

    public function testMaskObjectSessionToken()
    {
        $obj = new \stdClass();
        $obj->sessionToken = 'tok_abc123xyz789';
        $obj->amount = '25.00';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('tok_abc123xyz789', $content);
        $this->assertStringContainsString('xxxx', $content);
        $this->assertStringContainsString('25.00', $content);
    }

    public function testMaskObjectAccessToken()
    {
        $obj = new \stdClass();
        $obj->accessToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskObjectClientKey()
    {
        $obj = new \stdClass();
        $obj->clientKey = '7pK2Q3bZ9xR4mN6wY8vJ';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('7pK2Q3bZ9xR4mN6wY8vJ', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskObjectFingerPrint()
    {
        $obj = new \stdClass();
        $obj->fingerPrint = 'a1b2c3d4e5f6g7h8i9j0';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('a1b2c3d4e5f6g7h8i9j0', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskObjectMobileDeviceId()
    {
        $obj = new \stdClass();
        $obj->mobileDeviceId = 'DEVICE-UUID-12345-ABCDE';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('DEVICE-UUID-12345-ABCDE', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskObjectTransactionKey()
    {
        $obj = new \stdClass();
        $obj->transactionKey = '9Xp4Kz8mR2nQ5wLj';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('9Xp4Kz8mR2nQ5wLj', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskObjectCardNumberWithLastFour()
    {
        $obj = new \stdClass();
        $obj->cardNumber = '4111111111111111';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('4111111111111111', $content);
        $this->assertStringContainsString('xxxx', $content);
    }

    public function testMaskNestedObjectMerchantAuth()
    {
        $merchantAuth = new \stdClass();
        $merchantAuth->password = 'mySecretPassword';
        $merchantAuth->transactionKey = 'txnKey123';
        $merchantAuth->sessionToken = 'sessToken456';

        $request = new \stdClass();
        $request->merchantAuthentication = $merchantAuth;
        $request->amount = '100.00';

        $this->log->debug($request);
        $content = $this->getLogContent();

        $this->assertStringNotContainsString('mySecretPassword', $content);
        $this->assertStringNotContainsString('txnKey123', $content);
        $this->assertStringNotContainsString('sessToken456', $content);
        $this->assertStringContainsString('100.00', $content);
    }

    public function testNonSensitiveObjectFieldsPreserved()
    {
        $obj = new \stdClass();
        $obj->amount = '50.00';
        $obj->description = 'Test transaction';
        $obj->refId = 'REF-001';
        $this->log->debug($obj);
        $content = $this->getLogContent();

        $this->assertStringContainsString('50.00', $content);
        $this->assertStringContainsString('Test transaction', $content);
        $this->assertStringContainsString('REF-001', $content);
    }
}
