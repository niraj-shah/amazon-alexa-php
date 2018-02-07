<?php

namespace Alexa\Request;

use RuntimeException;
use InvalidArgumentException;
use DateTime;

abstract class Request {
	const TIMESTAMP_VALID_TOLERANCE_SECONDS = 30;
	const SIGNATURE_VALID_PROTOCOL = 'https';
	const SIGNATURE_VALID_HOSTNAME = 's3.amazonaws.com';
	const SIGNATURE_VALID_PATH = '/echo.api/';
	const SIGNATURE_VALID_PORT = 443;
	const CERT_SUBJECT_ALT_NAME = 'echo-api.amazon.com';

	public $requestId;
	public $timestamp;
	public $user;
	public $cert;
	public $signature;
	public $access_token;
	public $endpoint;

	public function __construct($data) {
		$this->requestId = $data['request']['requestId'];
		$this->timestamp = new DateTime($data['request']['timestamp']);
		$this->user = new User($data['session']['user']);
		$this->cert = $_SERVER['HTTP_SIGNATURECERTCHAINURL'] ?: null;
		$this->signature = $_SERVER['HTTP_SIGNATURE'] ?: null;
		$this->access_token = $data['context']['System']['apiAccessToken'];
		$this->endpoint = $data['context']['System']['apiEndpoint'];
	}

	public static function fromData($data) {
		$requestType = $data['request']['type'];

		if (!class_exists('\\Alexa\\Request\\' . $requestType)) {
			throw new RuntimeException('Unknown request type: ' . $requestType);
		}

		$className = '\\Alexa\\Request\\' . $requestType;

		$request = new $className($data);
		return $request;
	}

	public function validate() {
		$this->validateTimestamp();
	}

	private function validateTimestamp() {
		$now = new DateTime;
		$differenceInSeconds = $now->getTimestamp() - $this->timestamp->getTimestamp();

		if ($differenceInSeconds > self::TIMESTAMP_VALID_TOLERANCE_SECONDS) {
			throw new InvalidArgumentException('Request timestamp was too old. Possible replay attack.');
		}
	}

	public function validateCertificateUrl() {
		if (!$this->cert) {
			throw new RuntimeException('Certificate was not provided.');
		}

		$url = parse_url($this->cert);

		if ($url['scheme'] !== static::SIGNATURE_VALID_PROTOCOL) {
			throw new InvalidArgumentException('Protocol isn\'t secure. Request isn\'t from Alexa.');
		} else if ($url['host'] !== static::SIGNATURE_VALID_HOSTNAME) {
			throw new InvalidArgumentException('Certificate isn\'t from Amazon. Request isn\'t from Alexa.');
		} else if (strrpos($url['path'], static::SIGNATURE_VALID_PATH, -strlen($url['path'])) !== 0) {
			throw new InvalidArgumentException('Certificate isn\'t in "'.static::SIGNATURE_VALID_PATH.'" folder. Request isn\'t from Alexa.');
		} else if (isset($url['port']) && $url['port'] !== static::SIGNATURE_VALID_PORT) {
			throw new InvalidArgumentException('Port isn\'t ' . static::SIGNATURE_VALID_PORT. '. Request isn\'t from Alexa.');
		}
	}

	public function validateCertificateDetails() {
		if (!$this->cert) {
			throw new InvalidArgumentException('Certificate was not provided.');
		}

		$pem = @file_get_contents($this->cert);
		$details = openssl_x509_parse($pem);

		if ($details === false) {
			throw new InvalidArgumentException('Certificate could not be loaded. Request isn\'t from Alexa.');
		} else if (!strstr($details['extensions']['subjectAltName'], static::CERT_SUBJECT_ALT_NAME) ) {
			throw new InvalidArgumentException('Certificate isn\'t from Amazon. Request isn\'t from Alexa.');
		} else if ( $details['validFrom_time_t'] > time() ) {
			throw new InvalidArgumentException('Certificate isn\'t valid yet.');
		} else if ( $details['validTo_time_t'] < time() ) {
			throw new InvalidArgumentException('Certificate has expired.');
		}
	}

	public function validateSignature($data = null) {
		if (!$this->cert || !$this->signature) {
			throw new InvalidArgumentException('Request signature was not provided.');
		}

		$pem = @file_get_contents($this->cert);
		$pubKey = openssl_pkey_get_public($pem);
		$verify = openssl_verify($data, base64_decode($this->signature), $pubKey, 'sha1');

		if ($verify !== 1) {
			throw new InvalidArgumentException('Request signature was not valid.');
		}
	}
}
