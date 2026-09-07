<?php
/**
 * Created for plugin-component-access
 * Datetime: 28.02.2020 16:18
 * @author Timur Kasumov aka XAKEPEHOK
 */

namespace SalesRender\Plugin\Components\Access\Token;


use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use SalesRender\Plugin\Components\Access\PublicKey\PublicKey;
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\PluginReference;
use SalesRender\Plugin\Components\Info\Info;
use RuntimeException;

class GraphqlInputToken implements InputTokenInterface
{

    private UnencryptedToken $inputToken;

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

        $parser = new Parser(new JoseEncoder());
        $this->inputToken = $parser->parse($token);
        PublicKey::verify($this->inputToken);
    }

    public function getInputToken(): UnencryptedToken
    {
        return $this->inputToken;
    }

    public function getPluginReference(): PluginReference
    {
        $plugin = $this->getInputToken()->claims()->get('plugin');
        return new PluginReference(
            $this->getInputToken()->claims()->get('cid'),
            $plugin['alias'],
            $plugin['id'],
        );
    }

    public function getId(): string
    {
        return $this->getInputToken()->claims()->get('jti');
    }

    public function getCompanyId(): string
    {
        return $this->getInputToken()->claims()->get('cid');
    }

    public function getBackendUri(): string
    {
        return $this->getInputToken()->claims()->get('iss');
    }

    public function getOutputToken(): UnencryptedToken
    {
        $config = Configuration::forSymmetricSigner(
            new Sha512(),
            InMemory::plainText(Registration::find()->getHPT())
        );

        return $config->builder()
            ->withClaim('jwt', $this->getInputToken()->toString())
            ->withClaim('plugin', (string) Info::getInstance()->getType())
            ->getToken($config->signer(), $config->signingKey());
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
