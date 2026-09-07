<?php
/**
 * Created for plugin-component-access
 * Date: 20.11.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace SalesRender\Plugin\Components\Access\Registration;


use DateTimeImmutable;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use SalesRender\Plugin\Components\Access\PublicKey\PublicKey;
use SalesRender\Plugin\Components\Db\Components\Connector;
use SalesRender\Plugin\Components\Db\Model;
use SalesRender\Plugin\Components\Db\SinglePluginModelInterface;
use SalesRender\Plugin\Components\Guzzle\Guzzle;
use Psr\Http\Message\ResponseInterface;

class Registration extends Model implements SinglePluginModelInterface
{

    protected int $registeredAt;
    protected string $HPT;
    protected string $clusterUri;

    protected string $country;
    protected string $currency;

    /**
     * Registration constructor.
     * @param UnencryptedToken $token
     * @throws TokenVerificationException
     */
    public function __construct(UnencryptedToken $token)
    {
        $this->registeredAt = time();
        PublicKey::verify($token);
        $this->HPT = $token->claims()->get('HPT');
        $this->clusterUri = $token->claims()->get('iss');
        $this->country = $token->claims()->get('country');
        $this->currency = $token->claims()->get('currency');
    }

    /**
     * @return Registration|Model|null
     */
    public static function find(): ?Model
    {
        return parent::find();
    }

    public function getRegisteredAt(): int
    {
        return $this->registeredAt;
    }

    public function getHPT(): string
    {
        return $this->HPT;
    }

    public function getCountry(): string
    {
        return $this->country;
    }

    public function getCurrency(): string
    {
        return $this->currency;
    }

    public function getClusterUri(): string
    {
        return $this->clusterUri;
    }

    public function getSpecialRequestToken(array $body, int $ttl): UnencryptedToken
    {
        $reference = Connector::getReference();

        $config = Configuration::forSymmetricSigner(
            new Sha512(),
            InMemory::plainText($this->getHPT())
        );

        $now = new DateTimeImmutable();

        return $config->builder()
            ->issuedBy($_ENV['LV_PLUGIN_SELF_URI'])
            ->permittedFor($this->getClusterUri())
            ->withClaim('cid', $reference->getCompanyId())
            ->withClaim('plugin', [
                'alias' => $reference->getAlias(),
                'id' => $reference->getId(),
            ])
            ->withClaim('body', $body)
            ->expiresAt($now->modify("+{$ttl} seconds"))
            ->getToken($config->signer(), $config->signingKey());
    }

    /**
     * @param string $method
     * @param string $uri
     * @param array $body
     * @param int $ttl
     * @return Response
     * @throws GuzzleException
     */
    public function makeSpecialRequest(string $method, string $uri, array $body, int $ttl): ResponseInterface
    {
        return Guzzle::getInstance()->request(
            $method,
            $uri,
            ['json' => ['request' => $this->getSpecialRequestToken($body, $ttl)->toString()]]
        );
    }

    public static function schema(): array
    {
        return [
            'registeredAt' => ['INT', 'NOT NULL'],
            'HPT' => ['VARCHAR(512)', 'NOT NULL'],
            'country' => ['CHAR(2)', 'NOT NULL'],
            'currency' => ['CHAR(3)', 'NOT NULL'],
            'clusterUri' => ['VARCHAR(512)', 'NOT NULL'],
        ];
    }
}
