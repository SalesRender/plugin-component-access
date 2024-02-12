<?php
/**
 * Created for plugin-component-access
 * Date: 20.11.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace SalesRender\Plugin\Components\Access\Registration;


use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
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
    protected string $LVPT;
    protected string $clusterUri;

    protected string $country;
    protected string $currency;

    /**
     * Registration constructor.
     * @param Token $token
     * @throws TokenVerificationException
     */
    public function __construct(Token $token)
    {
        $this->registeredAt = time();
        PublicKey::verify($token);
        $this->LVPT = $token->getClaim('LVPT');
        $this->clusterUri = $token->getClaim('iss');
        $this->country = $token->getClaim('country');
        $this->currency = $token->getClaim('currency');
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

    public function getLVPT(): string
    {
        return $this->LVPT;
    }

    public function getCountry(): ?string
    {
        return $this->country;
    }

    public function getCurrency(): ?string
    {
        return $this->currency;
    }

    public function getClusterUri(): string
    {
        return $this->clusterUri;
    }

    public function getSpecialRequestToken(array $body, int $ttl): Token
    {
        $reference = Connector::getReference();

        $builder = new Builder();
        $builder->issuedBy($_ENV['LV_PLUGIN_SELF_URI']);
        $builder->permittedFor($this->getClusterUri());
        $builder->withClaim('cid', $reference->getCompanyId());
        $builder->withClaim('plugin', [
            'alias' => $reference->getAlias(),
            'id' => $reference->getId(),
        ]);
        $builder->withClaim('body', $body);
        $builder->expiresAt(time() + $ttl);

        return $builder->getToken(new Sha512(), new Key($this->getLVPT()));
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
            ['json' => ['request' => (string) $this->getSpecialRequestToken($body, $ttl)]]
        );
    }

    public static function schema(): array
    {
        return [
            'registeredAt' => ['INT', 'NOT NULL'],
            'LVPT' => ['VARCHAR(512)', 'NOT NULL'],
            'country' => ['CHAR(2)', 'NOT NULL'],
            'currency' => ['CHAR(3)', 'NOT NULL'],
            'clusterUri' => ['VARCHAR(512)', 'NOT NULL'],
        ];
    }
}