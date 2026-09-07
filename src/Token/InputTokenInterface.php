<?php
/**
 * Created for plugin-component-access
 * Date: 22.09.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace SalesRender\Plugin\Components\Access\Token;


use Lcobucci\JWT\UnencryptedToken;
use SalesRender\Plugin\Components\Db\Components\PluginReference;

interface InputTokenInterface
{

    public function __construct(string $token);

    public function getId(): string;

    public function getCompanyId(): string;

    public function getBackendUri(): string;

    public function getInputToken(): UnencryptedToken;

    public function getPluginReference(): PluginReference;

    public function getOutputToken(): UnencryptedToken;

    public static function getInstance(): ?InputTokenInterface;

    public static function setInstance(?InputTokenInterface $token): void;

}
