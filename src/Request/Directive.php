<?php
namespace Alexa\Request;

use Alexa\Request\Request;
use GuzzleHttp\Client as Guzzle;

class Directive {

	const DIRECTIVE_PATH = '/v1/directives';

	public $guzzle;
	public $requestId;
	public $access_token;
	public $endpoint;

	public function __construct($request) {
		$this->requestId = $request->requestId;
		$this->access_token = $request->access_token;
		$this->endpoint = $request->endpoint;
		$this->guzzle = new Guzzle;
	}

	public function speak($text) {
    $default_headers = [
        'Authorization'  => 'Bearer ' . $this->access_token,
        'Accept' => 'application/json'
      ];

    $payload['headers'] = $default_headers;

    $payload['http_errors'] = false;

    // set 5 second connection timeout, and 15 second response timeout
    $payload['connect_timeout'] = 5;

		$payload['json'] = [
			"header" => [
		    "requestId" => $this->requestId,
		  ],
			"directive" => [
				"type" => "VoicePlayer.Speak",
				"speech" => $text
			]
		];

    // make the request
    $response = $this->guzzle->request('POST', $this->endpoint . self::DIRECTIVE_PATH, $payload);

		return $response;
	}

}
