<?php

namespace DFUtils\Parser;

use phpbrowscap\Browscap;
use UAParser\Parser;

/**
 * A rate limiting class that implements the leaky bucket algorithm and 
 * makes use of in-memory NoSQL storage for fast operation
 */
class UA {
	/**
	 * The unique ID for the bucket to be manipulated
	 * Common values include IP address or browser fingerprint
	 * 
	 * @var string
	 */
	private $uaString;

	/**
	 * The unique ID for the bucket to be manipulated
	 * Common values include IP address or browser fingerprint
	 * 
	 * @var array
	 */
	private $results = [];

	private $cacheDir = '/var/www/app/app/data/';

	/**
	 * Creates a new leaky bucket style rate limiting object
	 * 
	 * @param string $UID Unique ID of the bucket, commonly a hash of the user's IP address
	 */
	public function __construct($uaString) {
		$this->uaString = $uaString;
	}

	private function processUAP() {
		$Parser = Parser::create();
		$Client = $Parser->parse();

		$this->results['uap'] = [
			'client_summary' => $Client->toString(),
			'ua_family' => $Client->ua->family,
			'ua_version' => [
					'major' => $Client->ua->major,
					'minor' => $Client->ua->minor,
					'patch' => $Client->ua->patch,
					'summary' => $Client->ua->toString()
				],
			'os_family' => $Client->os->family,
			'os_version' => [
					'major' => $Client->os->major,
					'minor' => $Client->os->minor,
					'patch' => $Client->os->patch,
					'summary' => $Client->os->toString()
				]
		];
	}

	private function processBrowserCap() {
		// Create a new Browscap object (loads or creates the cache)
		$bc = new Browscap($this->cacheDir . 'browsercap');

		// Get information about the current browser's user agent
		$current_browser = $bc->getBrowser();

		// Output the result
		echo '<pre>'; // some formatting issues ;)
		print_r($current_browser);
		echo '</pre>';
	}

	public function getResult() {

	}
}