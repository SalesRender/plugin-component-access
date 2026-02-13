# salesrender/plugin-component-access

Компонент безопасности экосистемы плагинов SalesRender. Обеспечивает аутентификацию на основе JWT, управление публичными RSA-ключами, регистрацию плагинов (хранение HPT token), а также обработку входящих и исходящих token между плагинами и бэкендом SalesRender.

## Установка

```bash
composer require salesrender/plugin-component-access
```

## Требования

- **PHP** >= 7.4.0
- **Расширения:** `ext-json`
- **Зависимости:**

| Пакет | Версия | Назначение |
|---|---|---|
| `lcobucci/jwt` | 3.3.3 | Разбор, создание и верификация JWT token |
| `league/uri` | 6.7.2 | Разбор URI для валидации издателя |
| `salesrender/plugin-component-db` | ^0.3.5 | Уровень моделей БД (Model, SinglePluginModelInterface) |
| `salesrender/plugin-component-guzzle` | ^0.3 | HTTP-клиент для загрузки public key и отправки запросов |
| `salesrender/plugin-component-info` | ^0.1.2 | Метаданные типа плагина для исходящих token |

## Обзор архитектуры

Компонент решает три ключевые задачи безопасности:

1. **Registration** -- хранение HandshakePluginToken (HPT), полученного при регистрации плагина
2. **PublicKey** -- загрузка и кэширование публичного RSA-ключа бэкенда для верификации JWT
3. **Token** -- верификация входящих JWT (RS512) и создание исходящих JWT (HS512)

### Поток аутентификации

```
SR Backend                              Plugin
    |                                     |
    |-- JWT (RS512, содержит HPT) ------->|
    |                                     |-- Верификация JWT через PublicKey
    |                                     |-- Извлечение HPT из JWT
    |                                     |-- Сохранение HPT в модели Registration
    |                                     |
    |<-- JWT (HS512, подписан HPT) -------|
    |                                     |
    |-- JWT (RS512, GraphQL запрос) ----->|
    |                                     |-- Верификация через PublicKey::verify()
    |                                     |-- Создание GraphqlInputToken
    |                                     |-- Обработка запроса
    |                                     |-- Создание исходящего JWT (HS512 с HPT)
    |<-- Ответ с output token ------------|
```

- **Входящие token** от бэкенда подписаны алгоритмом RS512 (приватный RSA-ключ). Плагин верифицирует их с помощью public key, загруженного с бэкенда.
- **Исходящие token**, создаваемые плагином, подписаны алгоритмом HS512 (HMAC), где в качестве секрета используется сохранённый HPT.

## Переменные окружения

| Переменная | Обязательна | Описание |
|---|---|---|
| `LV_PLUGIN_SELF_URI` | Да | URI самого плагина. Используется для проверки claim `aud` (audience) при верификации token |
| `LV_PLUGIN_COMPONENT_REGISTRATION_SCHEME` | Нет | Схема URI для валидации издателя. По умолчанию: `https` |
| `LV_PLUGIN_COMPONENT_REGISTRATION_HOSTNAME` | Нет | Список допустимых hostname через запятую. По умолчанию: `backend.leadvertex.com,backend.salesrender.com` |

## Справочник API

### Registration

**Namespace:** `SalesRender\Plugin\Components\Access\Registration\Registration`

Наследует `Model`, реализует `SinglePluginModelInterface`. Хранит HPT (HandshakePluginToken), полученный при регистрации плагина в бэкенде SR.

#### Методы

| Метод | Возвращает | Описание |
|---|---|---|
| `__construct(Token $token)` | | Верифицирует JWT через `PublicKey::verify()`, извлекает HPT, cluster URI, страну и валюту из claims |
| `static find()` | `?Model` | Находит запись Registration для текущей ссылки на плагин (унаследовано от SinglePluginModelInterface) |
| `getRegisteredAt()` | `int` | Unix-метка времени регистрации плагина |
| `getHPT()` | `string` | HandshakePluginToken -- общий секрет, используемый для подписи HS512 |
| `getCountry()` | `string` | Двухсимвольный код страны из registration token |
| `getCurrency()` | `string` | Трёхсимвольный код валюты из registration token |
| `getClusterUri()` | `string` | URI кластера бэкенда (issuer) для построения URL конечных точек API |
| `getSpecialRequestToken(array $body, int $ttl)` | `Token` | Создаёт JWT, подписанный HS512, с полезной нагрузкой и временем жизни для межсерверного взаимодействия |
| `makeSpecialRequest(string $method, string $uri, array $body, int $ttl)` | `ResponseInterface` | Создаёт подписанный JWT и отправляет HTTP-запрос на указанный URI |
| `static schema()` | `array` | Описание схемы базы данных |

#### Схема базы данных

| Столбец | Тип | Ограничение |
|---|---|---|
| `registeredAt` | INT | NOT NULL |
| `HPT` | VARCHAR(512) | NOT NULL |
| `country` | CHAR(2) | NOT NULL |
| `currency` | CHAR(3) | NOT NULL |
| `clusterUri` | VARCHAR(512) | NOT NULL |

---

### PublicKey

**Namespace:** `SalesRender\Plugin\Components\Access\PublicKey\PublicKey`

Наследует `Model`. Управляет публичными RSA-ключами для верификации JWT token от бэкенда SR. Ключи идентифицируются по MD5-хэшу (заголовок `pkey` в JWT token) и кэшируются в базе данных после первой загрузки.

#### Методы

| Метод | Возвращает | Описание |
|---|---|---|
| `protected __construct(string $publicKey)` | | Устанавливает `id` равным `md5($publicKey)`, сохраняет содержимое ключа |
| `protected getPublicKey()` | `Key` | Возвращает экземпляр `Lcobucci\JWT\Signer\Key` |
| `static verify(Token $token)` | `bool` | Полная верификация token: audience, схема издателя, hostname издателя, загрузка/кэширование public key, подпись RS512 |
| `static schema()` | `array` | Описание схемы базы данных |

#### Схема базы данных

| Столбец | Тип | Ограничение |
|---|---|---|
| `content` | TEXT | NOT NULL |

#### Этапы верификации в `PublicKey::verify()`

1. **Проверка audience** -- claim `aud` должен совпадать с `$_ENV['LV_PLUGIN_SELF_URI']`
2. **Проверка схемы** -- схема URI издателя (`iss`) должна совпадать с настроенной (по умолчанию `https`)
3. **Проверка hostname** -- hostname издателя должен входить в список разрешённых (поддерживается сопоставление поддоменов через regex)
4. **Поиск ключа** -- ищет кэшированный ключ по хэшу из заголовка `pkey`; если не найден, загружает с `{issuer_base}/pkey/{hash}`
5. **Верификация подписи** -- проверяет подпись RS512 с использованием public key
6. **Кэширование ключа** -- сохраняет public key в базу данных, если он был загружен впервые

---

### TokenVerificationException

**Namespace:** `SalesRender\Plugin\Components\Access\PublicKey\Exceptions\TokenVerificationException`

Наследует `Exception`. Выбрасывается методом `PublicKey::verify()` с определёнными кодами ошибок:

| Код | Сообщение | Значение |
|---|---|---|
| 100 | Audience mismatched '{aud}' | Claim `aud` token не совпадает с `LV_PLUGIN_SELF_URI` |
| 200 | Issuer scheme is not '{scheme}' | URI издателя использует неверную схему |
| 300 | Issuer hostname is not in '{hostnames}' | Hostname издателя отсутствует в списке разрешённых |
| 400 | Input token sign was not verified | Верификация подписи RS512 не пройдена |

---

### InputTokenInterface

**Namespace:** `SalesRender\Plugin\Components\Access\Token\InputTokenInterface`

Определяет контракт для обработчиков входящих token.

| Метод | Возвращает | Описание |
|---|---|---|
| `__construct(string $token)` | | Разбирает и верифицирует строку JWT |
| `getId()` | `string` | Идентификатор JWT (claim `jti`) |
| `getCompanyId()` | `string` | Идентификатор компании (claim `cid`) |
| `getBackendUri()` | `string` | URI бэкенда (claim `iss`) |
| `getInputToken()` | `Token` | Разобранный экземпляр `Lcobucci\JWT\Token` |
| `getPluginReference()` | `PluginReference` | Ссылка на плагин, построенная из claims `cid` и `plugin` |
| `getOutputToken()` | `Token` | Создаёт исходящий JWT, подписанный HS512, для взаимодействия с бэкендом |
| `static getInstance()` | `?InputTokenInterface` | Возвращает singleton-экземпляр |
| `static setInstance(?InputTokenInterface $token)` | `void` | Устанавливает singleton-экземпляр |

---

### GraphqlInputToken

**Namespace:** `SalesRender\Plugin\Components\Access\Token\GraphqlInputToken`

Реализует `InputTokenInterface`. Обрабатывает JWT token для запросов к GraphQL API. Использует паттерн singleton -- в рамках одного запроса может быть активен только один token.

| Метод | Возвращает | Описание |
|---|---|---|
| `__construct(string $token)` | | Разбирает JWT, верифицирует через `PublicKey::verify()`, выбрасывает `RuntimeException`, если экземпляр уже существует |
| `getInputToken()` | `Token` | Возвращает разобранный входящий JWT |
| `getPluginReference()` | `PluginReference` | Строит ссылку из claims `cid`, `plugin.alias`, `plugin.id` |
| `getId()` | `string` | Возвращает claim `jti` |
| `getCompanyId()` | `string` | Возвращает claim `cid` |
| `getBackendUri()` | `string` | Возвращает claim `iss` |
| `getOutputToken()` | `Token` | Создаёт JWT, подписанный HS512, содержащий исходный JWT и тип плагина; подписывается HPT |
| `static getInstance()` | `?InputTokenInterface` | Возвращает текущий singleton-экземпляр |
| `static setInstance(?InputTokenInterface $token)` | `void` | Устанавливает или сбрасывает singleton-экземпляр |

## Примеры использования

Все приведённые ниже примеры взяты из реальных плагинов и plugin-core.

### 1. Регистрация плагина (из [plugin-core](https://github.com/SalesRender/plugin-core) RegistrationAction)

Бэкенд SR отправляет JWT, содержащий HPT. Плагин разбирает token, устанавливает ссылку на плагин и сохраняет модель Registration:

```php
use Lcobucci\JWT\Parser;
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;
use SalesRender\Plugin\Components\Db\Components\PluginReference;

// Разбор JWT регистрации из тела запроса
$parser = new Parser();
$token = $parser->parse($request->getParsedBodyParam('registration'));

// Установка ссылки на плагин из claims token
Connector::setReference(new PluginReference(
    $token->getClaim('cid'),
    $token->getClaim('plugin')->alias,
    $token->getClaim('plugin')->id
));

// Удаление старой регистрации, если существует
if ($old = Registration::find()) {
    $old->delete();
}

// Создание и сохранение новой регистрации (JWT верифицируется внутри конструктора)
$registration = new Registration($token);
$registration->save();
```

### 2. Защищённый middleware -- верификация входящих запросов (из [plugin-core](https://github.com/SalesRender/plugin-core) ProtectedMiddleware)

Каждый защищённый endpoint проверяет входящий JWT из заголовка `X-PLUGIN-TOKEN`:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\Db\Components\Connector;

// Извлечение JWT из заголовка
$jwt = $request->getHeader('X-PLUGIN-TOKEN')[0] ?? '';

if (empty($jwt)) {
    throw new HttpException($request, 'X-PLUGIN-TOKEN not found', 401);
}

try {
    // Разбор и верификация JWT (внутри происходит проверка RS512)
    $token = new GraphqlInputToken($jwt);
    GraphqlInputToken::setInstance($token);
} catch (Exception $exception) {
    throw new HttpException($request, $exception->getMessage(), 403);
}

// Установка ссылки на плагин для запросов к БД с ограниченной областью видимости
Connector::setReference($token->getPluginReference());

// Проверка, что плагин зарегистрирован
if (Registration::find() === null) {
    throw new HttpException($request, 'Plugin was not registered', 403);
}
```

### 3. Использование output token для запросов к API (из [plugin-macros-example](https://github.com/SalesRender/plugin-macros-example))

После верификации output token используется для аутентификации запросов обратно к бэкенду:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\ApiClient\ApiClient;

$token = GraphqlInputToken::getInstance();
$client = new ApiClient(
    $token->getBackendUri() . 'companies/stark-industries/CRM',
    (string) $token->getOutputToken()
);
```

### 4. Отправка специальных запросов к бэкенду (из [plugin-core-logistic](https://github.com/SalesRender/plugin-core-logistic) BatchShippingHandler)

Метод `makeSpecialRequest` создаёт JWT, подписанный HS512, и отправляет его на бэкенд:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;

// Добавление заказов в партию отправки
Registration::find()->makeSpecialRequest(
    'PATCH',
    $uri,
    [
        'shippingId' => $shippingId,
        'orders' => $orders,
        'lockId' => $this->lockId,
    ],
    60 * 10 // TTL: 10 минут
);
```

### 5. Ручное создание token для специальных запросов (из [plugin-core-pbx](https://github.com/SalesRender/plugin-core-pbx) CdrSender)

Когда необходимо передать строку token в диспетчер отложенных запросов, а не отправлять немедленно:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;
use XAKEPEHOK\Path\Path;

$registration = Registration::find();
$uri = (new Path($registration->getClusterUri()))
    ->down('companies')
    ->down(Connector::getReference()->getCompanyId())
    ->down('CRM/plugin/pbx/cdr');

$ttl = 60 * 60 * 24; // 24 часа
$jwt = $registration->getSpecialRequestToken($this->cdr, $ttl);

// Использование строки token в отложенном запросе
$request = new SpecialRequest(
    'PATCH',
    (string) $uri,
    (string) $jwt,
    time() + $ttl,
    202
);
```

### 6. Интеграционный плагин -- отправка GraphQL-мутаций (из plugin-integration-taplink)

Использование `makeSpecialRequest` для выполнения GraphQL-мутаций на бэкенде:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;
use SalesRender\Plugin\Components\Db\Components\Connector;

$registration = Registration::find();
$reference = Connector::getReference();

$registration->makeSpecialRequest(
    'POST',
    "{$registration->getClusterUri()}/companies/{$reference->getCompanyId()}/CRM/plugin/integration",
    [
        'query' => 'mutation ($input: AddOrderInput!) { orderMutation { addOrder(input: $input) { id } } }',
        'variables' => ['input' => $variables],
    ],
    300 // TTL: 5 минут
);
```

### 7. Верификация специальных запросов (из [plugin-core](https://github.com/SalesRender/plugin-core) SpecialRequestAction)

Входящие специальные запросы от бэкенда верифицируются напрямую через `PublicKey::verify()`:

```php
use Lcobucci\JWT\Parser;
use SalesRender\Plugin\Components\Access\PublicKey\PublicKey;
use SalesRender\Plugin\Components\Access\Registration\Registration;

$token = (new Parser())->parse($request->getParsedBodyParam('request'));
PublicKey::verify($token);
$claims = json_decode(json_encode($token->getClaims()), true);

// Проверка наличия регистрации
if (Registration::find() === null) {
    throw new HttpException($request, 'Plugin was not registered', 403);
}
```

### 8. Проверка доступа к настройкам (из [plugin-core](https://github.com/SalesRender/plugin-core) SettingsAccessMiddleware)

Чтение claims из верифицированного singleton token для проверки прав доступа:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;

$isSettingsAllowed = GraphqlInputToken::getInstance()
    ->getInputToken()
    ->getClaim('settings', false);

if (!$isSettingsAllowed) {
    throw new HttpException($request, 'Access to settings is not allowed', 403);
}
```

### 9. Чтение метаданных регистрации (из plugin-logistic-sphere)

Получение страны и валюты, сохранённых при регистрации:

```php
use SalesRender\Plugin\Components\Access\Registration\Registration;

$currency = Registration::find()->getCurrency(); // например, "USD"
```

### 10. Пакетные операции -- использование singleton GraphqlInputToken (из [plugin-core](https://github.com/SalesRender/plugin-core) BatchPrepareAction)

Singleton token разделяется в рамках жизненного цикла запроса:

```php
use SalesRender\Plugin\Components\Access\Token\GraphqlInputToken;
use SalesRender\Plugin\Components\Batch\Batch;

$batch = new Batch(
    GraphqlInputToken::getInstance(),
    new ApiFilterSortPaginate($filters, $sort, 100),
    Translator::getLang(),
    $request->getParam('arguments', [])
);
$batch->save();
```

## Структура claims JWT

### Входящий JWT от бэкенда (RS512)

| Claim/Header | Описание |
|---|---|
| `pkey` (header) | MD5-хэш public key, использованного для подписи |
| `iss` | Издатель -- URI кластера бэкенда (например, `https://backend.salesrender.com`) |
| `aud` | Аудитория -- URI самого плагина (`LV_PLUGIN_SELF_URI`) |
| `cid` | Идентификатор компании |
| `plugin` | Объект с полями `alias` и `id` |
| `jti` | Идентификатор JWT (уникальный идентификатор) |
| `HPT` | HandshakePluginToken (присутствует только в token регистрации) |
| `country` | Двухсимвольный код страны (только в token регистрации) |
| `currency` | Трёхсимвольный код валюты (только в token регистрации) |
| `settings` | Логический флаг, разрешён ли доступ к настройкам (в GraphQL token) |

### Исходящий JWT от плагина (HS512)

#### Output Token (GraphqlInputToken::getOutputToken)

| Claim | Описание |
|---|---|
| `jwt` | Строка исходного входящего JWT |
| `plugin` | Тип плагина из `Info::getInstance()->getType()` |

#### Special Request Token (Registration::getSpecialRequestToken)

| Claim | Описание |
|---|---|
| `iss` | URI плагина (`LV_PLUGIN_SELF_URI`) |
| `aud` | URI кластера бэкенда |
| `cid` | Идентификатор компании |
| `plugin` | Объект с полями `alias` и `id` |
| `body` | Массив полезной нагрузки запроса |
| `exp` | Время истечения (`time() + $ttl`) |

## Смотрите также

- [salesrender/plugin-component-db](https://github.com/SalesRender/plugin-component-db) -- Уровень моделей БД, `Model`, `SinglePluginModelInterface`
- [salesrender/plugin-component-guzzle](https://github.com/SalesRender/plugin-component-guzzle) -- HTTP-клиент для загрузки public key и отправки специальных запросов
- [salesrender/plugin-component-info](https://github.com/SalesRender/plugin-component-info) -- Метаданные и тип плагина
- [salesrender/plugin-core](https://github.com/SalesRender/plugin-core) -- Ядро фреймворка плагинов с `ProtectedMiddleware`, `RegistrationAction`, `SpecialRequestAction`
