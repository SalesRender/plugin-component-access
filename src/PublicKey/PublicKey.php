<?php
/**
 * Created for plugin-component-access
 * Date: 20.11.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace SalesRender\Plugin\Components\Access\PublicKey;


use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException;
use SalesRender\Plugin\Components\Db\Model;
use SalesRender\Plugin\Components\Guzzle\Guzzle;
use League\Uri\UriString;

class PublicKey extends Model
{

    protected string $content;

    protected function __construct(string $publicKey)
    {
        $this->id = md5($publicKey);
        $this->content = $publicKey;
    }

    protected function getPublicKey(): InMemory
    {
        return InMemory::plainText($this->content);
    }

    public static function schema(): array
    {
        return [
            'content' => ['TEXT', 'NOT NULL'],
        ];
    }

    /**
     * @param UnencryptedToken $token
     * @return bool
     * @throws TokenVerificationException
     */
    public static function verify(UnencryptedToken $token): bool
    {
        if (!$token->isPermittedFor($_ENV['LV_PLUGIN_SELF_URI'])) {
            $aud = implode(',', $token->claims()->get('aud', []));
            throw new TokenVerificationException("Audience mismatched '{$aud}'", 100);
        }

        $endpoint = UriString::parse($token->claims()->get('iss'));

        $scheme = $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_SCHEME'] ?? 'https';
        if ($endpoint['scheme'] !== $scheme) {
            throw new TokenVerificationException("Issuer scheme is not '{$scheme}'", 200);
        }

        $hostnames = explode(
            ',',
            $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_HOSTNAME'] ?? ['backend.leadvertex.com', 'backend.salesrender.com']
        );
        $hostnames = array_map('trim', $hostnames);

        $invalidHostname = true;
        foreach ($hostnames as $hostname) {
            if (preg_match('~(^|\.)' . preg_quote($hostname) . '$~ui', $endpoint['host'])) {
                $invalidHostname = false;
                break;
            }
        }
        if ($invalidHostname) {
            throw new TokenVerificationException(sprintf("Issuer hostname is not in '{%s}'",
                implode(',', $hostnames)), 300);
        }

        $hash = $token->headers()->get('pkey');
        $key = self::findById($hash);

        if (!$key) {
            $endpoint['path'] = null;
            $endpoint['query'] = null;
            $endpoint['fragment'] = null;
            $uri = UriString::build($endpoint) . "/pkey/{$hash}";
            $publicKey = Guzzle::getInstance()->get($uri)->getBody()->getContents();
            $key = new self($publicKey);
        }

        $validator = new Validator();
        if (!$validator->validate($token, new SignedWith(new Sha512(), $key->getPublicKey()))) {
            throw new TokenVerificationException("Input token sign was not verified", 400);
        }

        if ($key->isNewModel()) {
            $key->save();
        }

        return true;
    }
}
