<?php
/**
 * Created for plugin-component-access
 * Datetime: 28.02.2020 16:18
 * @author Timur Kasumov aka XAKEPEHOK
 */

namespace SalesRender\Plugin\Components\Access\Token;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use SalesRender\Plugin\Components\Access\PublicKey\PublicKey;
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\PluginReference;
use SalesRender\Plugin\Components\Info\Info;
use RuntimeException;

class GraphqlInputToken implements InputTokenInterface
{

    private Token $inputToken;

    private static ?GraphqlInputToken $instance = null;

    /**
     * GraphqlInputToken constructor.
     * @param string $token
     * @throws TokenVerificationException
     */
    public function __construct(string $token)
    {
        if (!is_null(self::$instance)) {
            throw new RuntimeException('Some token already loaded');
        }

        $this->inputToken = (new Parser())->parse($token);
        PublicKey::verify($this->inputToken);
    }

    public function getInputToken(): Token
    {
        return $this->inputToken;
    }

    public function getPluginReference(): PluginReference
    {
        return new PluginReference(
            $this->getInputToken()->getClaim('cid'),
            $this->getInputToken()->getClaim('plugin')->alias,
            $this->getInputToken()->getClaim('plugin')->id,
        );
    }

    public function getId(): string
    {
        return $this->getInputToken()->getClaim('jti');
    }

    public function getCompanyId(): string
    {
        return $this->getInputToken()->getClaim('cid');
    }

    public function getBackendUri(): string
    {
        return $this->getInputToken()->getClaim('iss');
    }

    public function getOutputToken(): Token
    {
        return (new Builder())
            ->withClaim('jwt', (string) $this->getInputToken())
            ->withClaim('plugin', (string) Info::getInstance()->getType())
            ->getToken(new Sha512(), new Key(Registration::find()->getHPT()));
    }

    public static function getInstance(): ?InputTokenInterface
    {
        return self::$instance;
    }

    public static function setInstance(?InputTokenInterface $token): void
    {
        self::$instance = $token;
    }
}