<?php

namespace DFUtils\Parser;

use phpbrowscap\Browscap;
use UAParser\Parser;
use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\DeviceParserAbstract;
use Detection\MobileDetect;

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
	public function __construct($uaString, $cacheDir) {
		$this->uaString = $uaString;
		$this->cacheDir = $cacheDir;

		$this->processUAP();
		$this->processDeviceDetector();
		$this->processMobileDetect();	
	}

	private function processUAP() {
		$Parser = Parser::create();
		$Client = $Parser->parse($this->uaString);

		$this->results['uap'] = [
			'client_summary' => $Client->toString(),
			'ua_family' => $Client->ua->family,
			'ua_version' => [
					'major' => (int) $Client->ua->major,
					'minor' => (int) $Client->ua->minor,
					'patch' => (int) $Client->ua->patch,
					'summary' => $Client->ua->toString()
				],
			'os_family' => $Client->os->family,
			'os_version' => [
					'major' => (int) $Client->os->major,
					'minor' => (int) $Client->os->minor,
					'patch' => (int) $Client->os->patch,
					'summary' => $Client->os->toString()
				]
		];
	}
/*
	private function processBrowserCap() {
		// Create a new Browscap object (loads or creates the cache)
		$Parser = new Browscap($this->cacheDir . 'browsercap');

		// Get information about the current browser's user agent
		$current_browser = $Parser->getBrowser($this->uaString);

		// Output the result
		echo '<pre>'; // some formatting issues ;)
		print_r($current_browser);
		echo '</pre>';
	}
*/
	private function processDeviceDetector() {
		$Parser = new DeviceDetector($this->uaString);
		$Parser->parse();

		$clientData = [
			'type' => null,
			'name' => null,
			'brand' => null,
			'model' => null
		];

		$osData = [
			'name' => null,
			'short_name' => null,
			'version' => null,
			'platform' => null
		];

		$renderingEngine = [
			'name' => null,
			'version' => [
					'major' => null,
					'minor' => null,
					'patch' => null,
					'summary' => null
				]
		];

		$botInfo = [
			'name' => null,
			'category' => null,
			'url' => null,
			'vendor' => [
				'name' => null,
				'url' => null
			]
		];

		if ($Parser->isBot()) {
			// handle bots,spiders,crawlers,...
			$botInfo = $Parser->getBot();

			$botInfo = [
				'name' => $botInfo['name'],
				'category' => $botInfo['category'],
				'url' => $botInfo['url'],
				'vendor' => [
					'name' => $botInfo['producer']['name'],
					'url' => $botInfo['producer']['url']
				]
			];
		} else {
			$clientInfo = $Parser->getClient(); // holds information about browser, feed reader, media player, ...
			$osInfo = $Parser->getOs();
			$device = $Parser->getDevice();
			$brand = $Parser->getBrandName();
			$model = $Parser->getModel();

			$clientData = [
				'type' => $clientInfo['type'],
				'name' => $clientInfo['name'],
				'brand' => $brand,
				'model' => $model
			];

			$osData = [
				'name' => $osInfo['name'],
				'short_name' => $osInfo['short_name'],
				'version' => $osInfo['version'],
				'platform' => $osInfo['platform'] //64 bit?
			];

			$versionParts = explode('.', $clientInfo['engine_version']);
			$renderingEngine = [
				'name' => $clientInfo['engine'],
				'version' => [
						'major' => (int) (isset($versionParts[0])) ? $versionParts[0] : null,
						'minor' => (int) (isset($versionParts[1])) ? $versionParts[1] : null,
						'patch' => (int) (isset($versionParts[2])) ? $versionParts[2] : null,
						'summary' => trim($clientInfo['engine'] . ' ' . $clientInfo['engine_version'])
					]
			];
		}

		$this->results['device_detector'] = [
			'is_bot' => $Parser->isBot(),
			'bot_info' => $botInfo,
			'rendering_engine' => $renderingEngine,
			'client_data' => $clientData,
			'os_data' => $osData
		];
	}

	public function processMobileDetect() {
		$detect = new MobileDetect;
		$detect->setUserAgent($this->uaString);

		$this->results['mobile_detect'] = [
			'is_mobile' => $detect->isMobile(),
			'is_tablet' => $detect->isTablet(),
			'is_desktop' => !$detect->isMobile() && !$detect->isTablet()
		];
	}

	public function getResult() {
		$return = $this->results['uap'];
		$return['ua_type'] = $this->results['device_detector']['client_data']['type'];

		$return['bot_info'] = $this->results['device_detector']['bot_info'];
		$return['os_meta'] = $this->results['device_detector']['os_data'];

		$return['ua_rendering_engine'] = $this->results['device_detector']['rendering_engine']['name'];
		$return['ua_rendering_engine_version'] = $this->results['device_detector']['rendering_engine']['version'];

		$return['device'] = $this->results['mobile_detect'];
		$return['device']['brand'] = $this->results['device_detector']['client_data']['brand'];
		$return['device']['model'] = $this->results['device_detector']['client_data']['model'];
		$return['client'] = [
			'bot' => $this->results['device_detector']['is_bot'],
			'user' => !$this->results['device_detector']['is_bot'],
		];

		array_walk_recursive($return, function(&$input) {
			$input = (($input === "") ? null : $input);
		});

		if ($return['ua_type'] === null) {
			$return['ua_type'] = $return['bot_info']['category'];
		}

		return $return;
	}
}
