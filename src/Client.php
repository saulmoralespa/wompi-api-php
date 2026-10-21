<?php

namespace Saulmoralespa\Wompi;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Utils;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;

class Client
{
    const API_BASE_URL = "https://production.wompi.co/";
    const SANDBOX_API_BASE_URL = "https://sandbox.wompi.co/";
    const API_VERSION = "v1";
    protected static bool $sandbox = false;

    public function __construct(
        private $keyPrivate,
        private $keyPublic,
        private $keyIntegrety
    ) {
    }

    public function sandbox(): self
    {
        self::$sandbox = true;
        return $this;
    }

    public static function getBaseURL(): string
    {
        return self::$sandbox ? self::SANDBOX_API_BASE_URL : self::API_BASE_URL;
    }
    public function client(): GuzzleClient
    {
        return new GuzzleClient([
            "base_uri" => self::getBaseURL() . self::API_VERSION . "/",
        ]);
    }

    /**
     * @throws GuzzleException|RuntimeException
     */
    public function getKeysTokenization(): string
    {
        $decoded = $this->makeRequest("GET", "tokens/keys/tokenization");
        $pem = $decoded['data']['publicKey'] ?? null;

        if (!$pem) {
            throw new RuntimeException('Public key missing in response');

        }

        $pem = self::normalizePem($pem);
        return $pem;
    }

    /**
     * @throws \Exception|GuzzleException
     */
    public function cardToken(array $data, $isEncrypted = false): array
    {
        if ($isEncrypted) {
            $publicKey = $this->getKeysTokenization();
            $encrypted = self::encrypt($data, $publicKey);
            $data = [
                "payload" => $encrypted
            ];
        }
        
        return $this->makeRequest("POST", "tokens/cards", [
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function nequiToken(array $data): array
    {
        return $this->makeRequest("POST", "tokens/nequi", [
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function getStatusSubscriptionNequi(string $token): array
    {
        return $this->makeRequest("GET", "tokens/nequi/$token");
    }

    /**
     * @throws GuzzleException
     */
    public function daviplataToken(array $data): array
    {
        return $this->makeRequest("POST", "tokens/daviplata", [
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function bancolombiaToken(array $data): array
    {
        return $this->makeRequest("POST", "tokens/bancolombia_transfer", [
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function getStatusSubscriptionDaviplata(string $token): array
    {
        return $this->makeRequest("GET", "tokens/daviplata/$token");
    }

    /**
     * @throws GuzzleException
     */
    public function getStatusSubscriptionBancolombia(string $token): array
    {
        return $this->makeRequest("GET", "tokens/bancolombia_transfer/$token");
    }

    /**
     * @throws GuzzleException
     */
    public function getAcceptanceTokens(): array
    {
        return $this->makeRequest("GET", "merchants/$this->keyPublic");
    }

    /**
     * @throws GuzzleException
     */
    public function createSource(array $data): array
    {
        return $this->makeRequest("POST", "payment_sources", [
            "headers" => [
                "Authorization" => "Bearer " . $this->keyPrivate,
            ],
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function cancelSubscription(int $sourceId): array
    {
        return $this->makeRequest("PUT", "payment_sources/$sourceId/void", [
            "headers" => [
                "Authorization" => "Bearer " . $this->keyPrivate,
            ]
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function transaction(array $data): array
    {
        $data["signature"] = $this->getSignature($data);

        return $this->makeRequest("POST", "transactions", [
            "headers" => [
                "Authorization" => "Bearer " . $this->keyPrivate,
            ],
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function getTransaction(string $transactionId): array
    {
        return $this->makeRequest("GET", "transactions/$transactionId");
    }

    /**
     * @throws GuzzleException
     */
    public function createPaymentLink(array $data): array
    {
        return $this->makeRequest("POST", "payment_links", [
            "headers" => [
                "Authorization" => "Bearer " . $this->keyPrivate,
            ],
            "json" => $data
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function getPaymentLink(string $id): array
    {
        return $this->makeRequest("GET", "payment_links/$id");
    }

    /**
     * @throws GuzzleException
     * @throws \Exception
     */
    private function makeRequest(string $method, string $uri, array $newOptions = []): array
    {
        try {
            $options = [
                "headers" => [
                    "Authorization" => "Bearer " . $this->keyPublic,
                    "Content-Type" => "application/json"
                ]
            ];

            $options = [
                ...$options, ...$newOptions
            ];

            $res = $this->client()->request($method, $uri, $options);
            $content =  $res->getBody()->getContents();
            return self::responseArray($content);
        } catch (RequestException $exception) {
            $content = $exception->getResponse()->getBody()->getContents();
            $response = self::responseArray($content);
            $errorMessage = $this->handleErrors($response) ?? $exception->getMessage();
            throw new \Exception($errorMessage);
        } catch (\Exception $exception) {
            throw new \Exception($exception->getMessage());
        }
    }

    public static function responseArray(string $content): array
    {
        return Utils::jsonDecode($content, true);
    }

    public static function normalizePem(string $raw): string
    {
        $cleaned = str_replace(["\r", '\\n'], ['', "\n"], trim($raw));
        $base64 = preg_replace(
            '/\s+/',
            '',
            str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'], '', $cleaned)
        );

        return "-----BEGIN PUBLIC KEY-----\n" . $base64 . "\n-----END PUBLIC KEY-----";
    }

    public static function encrypt(array $payload, string $pemKey): string
    {
        $keyEncryption = new AlgorithmManager([new RSAOAEP256()]);
        $contentEncryption = new AlgorithmManager([new A256GCM()]);
        $compressionManager = new CompressionMethodManager([]); // no compression

        $jwk = JWKFactory::createFromKey($pemKey, null, ['use' => 'enc']);

        $jweBuilder = new JWEBuilder($keyEncryption, $contentEncryption, $compressionManager);
        $jwe = $jweBuilder
            ->create()
            ->withPayload(json_encode($payload, JSON_THROW_ON_ERROR))
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A256GCM',
            ])
            ->addRecipient($jwk)
            ->build();

        $serializer = new CompactSerializer();
        return $serializer->serialize($jwe, 0);
    }

    public function handleErrors(array $response): ?string
    {
        if ((array_key_exists('error', $response) &&
                is_array($response['error']))
        ) {
            $errors = $response['error']['messages'] ?? $response['error']['reason']  ?? [];

            if(is_string($errors)) return $errors;

            $arr = [];

            foreach($errors as $index => $error) {
                $arr[] = "$index: " . implode(", ", $error);
            }

            return implode(PHP_EOL, $arr);
        }

        return null;
    }

    public function getSignature(array $data): string
    {
        $stringToEncrypt = "{$data['reference']}{$data['amount_in_cents']}{$data['currency']}$this->keyIntegrety";
        return hash("sha256", $stringToEncrypt);
    }
}