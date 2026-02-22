# envoy-socks5-filter

SOCKS5 + Shadowsocks proxy для Envoy с поддержкой AEAD шифрования.

## Что это?

Network Filter для Envoy, который:
1. Принимает SOCKS5 соединения от клиентов (браузер, curl)
2. Шифрует трафик по протоколу Shadowsocks (AEAD)
3. Отправляет на удалённые SS серверы

## Статус проекта

| Компонент | Статус |
|-----------|--------|
| SOCKS5 парсер | ✅ Работает |
| Shadowsocks AEAD | ✅ Работает |
| SS Cluster + LB | ✅ Работает (15/15 серверов) |
| Health Check | ✅ Работает |
| Метрики Envoy | ✅ Реализовано |
| Hot Reload конфигов | ✅ Реализовано |
| Envoy Network Filter | ✅ Код готов |
| Bazel BUILD | ✅ Готов |
| GitHub CI/CD | ✅ Настроен |
| Docker | ✅ Готов |

## Архитектура

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           КЛИЕНТ (браузер)                              │
│                                 │                                        │
│                         SOCKS5 запрос                                    │
│                     ┌───────────┴───────────┐                            │
│                     │  CONNECT example.com:443                           │
│                     └───────────┬───────────┘                            │
└─────────────────────────────────┼───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ENVOY + SOCKS5 FILTER                            │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────────────┐  │
│  │ socks5.hpp  │──▶│ socks5_filter│──▶│ shadowsocks.hpp              │  │
│  │  (парсинг)  │   │   (роутинг)  │   │  (AEAD шифрование)           │  │
│  └─────────────┘   └──────────────┘   └──────────────────────────────┘  │
│                                                │                         │
│                                     ┌──────────┴──────────┐              │
│                                     │  Salt + Encrypted   │              │
│                                     │  [addr][payload]    │              │
│                                     └──────────┬──────────┘              │
└────────────────────────────────────────────────┼────────────────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        SHADOWSOCKS SERVER (VPS)                         │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Decrypt → Parse Target → TCP Connect → Forward → Encrypt Back  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                  │                                       │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           TARGET (example.com)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Механика проксирования: Обычный vs Shadowsocks

### Обычный SOCKS5 запрос (без шифрования)

```
Клиент → SOCKS5 Proxy → Интернет

1. [VER=5][NMETHODS=1][METHOD=0]     ← Клиент: хочу подключиться
2. [VER=5][METHOD=0]                  ← Сервер: ОК, без авторизации
3. [VER=5][CMD=1][RSV][ATYP=3]       ← Клиент: CONNECT example.com:443
   [LEN=11][example.com][PORT=443]
4. [VER=5][REP=0][RSV][ATYP][ADDR]   ← Сервер: подключено
5. <raw TCP data>                     ← Двустороний туннель
```

**Проблема:** Провайдер видит:
- IP адрес целевого сервера
- Факт SOCKS5 соединения
- Объём трафика

### Shadowsocks запрос (с AEAD шифрованием)

```
Клиент → SOCKS5 Filter → SS Server → Интернет

1. TCP Connect к SS Server (82.38.31.35:8080)

2. Отправка первого пакета:
   ┌────────────────────────────────────────────────────────────┐
   │ SALT (32 bytes)                                            │
   ├────────────────────────────────────────────────────────────┤
   │ Encrypted Length (2 bytes) + TAG (16 bytes)                │
   ├────────────────────────────────────────────────────────────┤
   │ Encrypted Payload:                                         │
   │   [ATYP=3][LEN][example.com][PORT=443][HTTP request...]    │
   │   + TAG (16 bytes)                                         │
   └────────────────────────────────────────────────────────────┘

3. Ответ от SS сервера:
   ┌────────────────────────────────────────────────────────────┐
   │ SALT (32 bytes)                                            │
   ├────────────────────────────────────────────────────────────┤
   │ Encrypted Length + TAG                                     │
   ├────────────────────────────────────────────────────────────┤
   │ Encrypted Response + TAG                                   │
   └────────────────────────────────────────────────────────────┘
```

**Что видит провайдер:**
- Соединение с IP (82.38.31.35:8080)
- Случайные байты (соль + зашифрованные данные)
- **НЕ ВИДИТ:** целевой адрес, содержимое, протокол

### Сравнительная таблица

| Параметр | Обычный SOCKS5 | Shadowsocks |
|----------|----------------|-------------|
| Шифрование | ❌ Нет | ✅ AEAD (ChaCha20/AES-GCM) |
| Целевой адрес | 👁 Виден | 🔒 Зашифрован |
| Определение протокола | 👁 Легко | ❌ Невозможно |
| Replay-атаки | ⚠️ Возможны | ✅ Защита (salt + nonce) |
| Overhead | ~10 байт | ~64 байта на chunk |

## Структура кода

```
envoy-socks5-filter/
├── include/
│   ├── socks5/
│   │   └── socks5.hpp          # SOCKS5 протокол (RFC 1928)
│   └── shadowsocks/
│       └── shadowsocks.hpp     # SS AEAD криптография
├── src/filter/
│   ├── socks5_filter.h         # Envoy Network Filter
│   ├── socks5_filter.cc        # Реализация state machine
│   └── config.cc               # Factory + регистрация
├── proto/
│   └── socks5_filter.proto     # Protobuf конфигурация
├── test/
│   ├── socks5_test.cc          # Unit тесты (GTest)
│   ├── standalone_test.cc      # Standalone проверка
│   └── ss_test.cc              # Тест SS серверов
├── BUILD                        # Bazel для Envoy
└── CMakeLists.txt              # CMake для standalone
```

## Load Balancing (ss_cluster.hpp)

### Политики балансировки

| Политика | Описание |
|----------|----------|
| `ROUND_ROBIN` | Последовательный выбор серверов |
| `LEAST_CONNECTIONS` | Сервер с минимумом активных соединений |
| `RANDOM` | Случайный выбор |
| `WEIGHTED_LATENCY` | Сервер с наименьшей задержкой (default) |

### Health Check

- TCP connect проверка каждые 30 сек (настраивается)
- Автоматическое исключение недоступных серверов
- Метрика `healthy_servers` обновляется в реальном времени

### Тест кластера

```bash
./cmake_build/cluster_test
# Output:
# ✓ Netherlands #33851 (82.38.31.35:8080) latency=0ms
# ✓ UnitedKingdom #34271 (149.102.132.180:80) latency=0ms
# ...
# Healthy servers: 15/15
```

## Hot Reload конфигурации

Файл `keys.json` мониторится на изменения:
- Проверка `mtime` каждые 60 сек (настраивается)
- При изменении — атомарная замена кластера
- Существующие соединения продолжают работать со старым кластером

## Метрики Envoy

```
socks5_ss.connections_total        # Всего соединений
socks5_ss.connections_success      # Успешных соединений
socks5_ss.connections_failed       # Неудачных соединений
socks5_ss.active_connections       # Текущих активных
socks5_ss.healthy_servers          # Здоровых серверов
socks5_ss.bytes_sent               # Байт отправлено
socks5_ss.bytes_received           # Байт получено
socks5_ss.upstream_latency_ms      # Гистограмма задержки
```

## Криптография (shadowsocks.hpp)

### Поддерживаемые шифры

| Метод | Ключ | Salt | Nonce | Использование |
|-------|------|------|-------|---------------|
| chacha20-ietf-poly1305 | 32 | 32 | 12 | Мобильные, ARM |
| aes-256-gcm | 32 | 32 | 12 | Десктоп, x86 |
| aes-128-gcm | 16 | 16 | 12 | Legacy |

### Key Derivation

```cpp
// 1. Password → PSK (EVP_BytesToKey с MD5)
PSK = derive_key("password", key_size)

// 2. PSK + Salt → Subkey (HKDF-SHA1)
Subkey = HKDF(PSK, Salt, info="ss-subkey")

// 3. Subkey → AEAD Cipher
cipher = AeadCipher(Subkey)
```

### AEAD Chunk Format

```
┌──────────────────────────────────────────────────────────────┐
│ Encrypted Length (2B) │ Auth Tag (16B) │ Encrypted Data │ Auth Tag (16B) │
└──────────────────────────────────────────────────────────────┘
     ↑                                         ↑
     └── Big-endian, max 0x3FFF                └── Actual payload
```

## Тестирование

### Быстрый тест

```bash
cd envoy-socks5-filter

# Компиляция
c++ -std=c++17 -I include test/ss_test.cc -o ss_test -lcrypto -lssl

# Запуск (использует ../gost-proxy/data/keys.json)
./ss_test
```

### Результат

```
=== Shadowsocks Connection Test ===
Testing: Netherlands #33851 / OutlineKeys.com
  Server: 82.38.31.35:8080
  Method: chacha20-ietf-poly1305
  Result: OK (connection works!)
...
Tested: 5, Success: 5, Failed: 0
```

## Конфигурация Envoy

```yaml
static_resources:
  listeners:
  - name: socks5_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 1080
    filter_chains:
    - filters:
      - name: envoy.filters.network.socks5
        typed_config:
          "@type": type.googleapis.com/socks5.v3.Socks5Filter
          stat_prefix: socks5
          auth_required: false
          
  clusters:
  - name: default_egress
    connect_timeout: 5s
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
```

## SOCKS5 Protocol Overview

```
Client                                      Server
   │                                           │
   │──── Method Selection (0x05, n_methods) ──▶│
   │                                           │
   │◀─── Method Response (0x05, method) ───────│
   │                                           │
   │──── Auth (if required) ──────────────────▶│
   │                                           │
   │◀─── Auth Response ────────────────────────│
   │                                           │
   │──── Request (CONNECT dst:port) ──────────▶│
   │                                           │
   │◀─── Reply (success/fail) ─────────────────│
   │                                           │
   │◀────────── DATA RELAY ───────────────────▶│
```

## Popular SOCKS5 C/C++ Libraries (Research)

| Library | Stars | Language | Notes |
|---------|-------|----------|-------|
| [3proxy](https://github.com/3proxy/3proxy) | 4.9k | C | Full-featured proxy server |
| [microsocks](https://github.com/rofl0r/microsocks) | 2k | C | Minimal SOCKS5 server |
| [hev-socks5-server](https://github.com/heiher/hev-socks5-server) | 510 | C | Fast, lightweight |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | 1.7k | C | TUN-based tunnel |

This project provides a **clean C++17 implementation** optimized for Envoy integration.

## GitHub CI/CD

Проект автоматически собирается в GitHub Actions:

```bash
# Workflow triggers
- push to main/develop
- pull requests to main
- manual trigger via workflow_dispatch
```

### Build Pipeline

| Job | Описание | Время |
|-----|----------|-------|
| `build` | Сборка Envoy с фильтром | ~120 мин |
| `test-standalone` | Standalone тесты (ss_test, cluster_test) | ~5 мин |
| `docker` | Docker image build | ~15 мин |

### Артефакты

После успешной сборки доступны:
- `envoy-socks5-ss` — скомпилированный бинарник Envoy
- `ghcr.io/<owner>/envoy-socks5-ss:latest` — Docker image

## Docker

### Быстрый старт

```bash
# Запуск с docker-compose
docker-compose up -d

# С метриками (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

### Сборка локально

```bash
# Build Docker image
docker build -t envoy-socks5-ss .

# Run
docker run -d \
  -p 1080:1080 \
  -p 9901:9901 \
  -v $(pwd)/examples/envoy-socks5-ss.yaml:/etc/envoy/envoy.yaml \
  envoy-socks5-ss
```

### Мониторинг

Grafana доступна на `http://localhost:3000` (admin/admin)

Ключевые метрики:
- `envoy_socks5_ss_connections_total` — всего соединений
- `envoy_socks5_ss_active_connections` — активных сейчас
- `envoy_socks5_ss_bytes_tx_total` / `bytes_rx_total` — трафик
- `envoy_socks5_ss_errors_total` — ошибки
- `envoy_socks5_ss_healthy_servers` — здоровые сервера

## Bazel Build (для разработки)

```bash
# Сборка Envoy с нашим фильтром
bazel build //:envoy --config=release

# Сборка только фильтра
bazel build //source/extensions/filters/network/socks5_ss:config

# Тесты
bazel test //test:socks5_filter_test
```

## Локальная разработка (CMake, без Envoy)

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Тесты
./ss_test
./cluster_test
```

## Лицензия

Apache 2.0
