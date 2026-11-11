# xray-guard — защита TCP/443 для x-ui / Xray

## Назначение

`xray-guard` — набор правил **nftables** и служб **systemd**, ограничивающий чрезмерные новые TCP-подключения к порту **443**, на котором работает Xray (VLESS под управлением x-ui).

Защита действует **на входящие IPv4 TCP-пакеты к 443**. Она не является прокси и не анализирует содержимое VLESS. Маршрутизация Xray → sing-box → `proxy-out` — отдельный механизм, не относящийся к этой защите.

> Этот README описывает конфигурацию, настроенную на сервере. Перед изменениями проверьте актуальное состояние командами ниже: файлы и правила могли быть изменены после настройки.

## Как работает фильтр

Пакет IPv4 TCP на порт 443 попадает в цепочку `input` таблицы `inet xray_guard` (hook `input`, priority `-10`, policy `accept`) и передаётся в `check443_v4`.

1. Сначала проверяется набор `trusted4`. Если IP есть в нём, обработка правил `xray_guard` для этого пакета прекращается (`return`): ограничения по количеству и частоте новых подключений не применяются.
2. Для остальных адресов правило `ct state new` ограничивает количество **одновременных отслеживаемых соединений** от одного IPv4: `ct count over 60` → `drop`.
3. Следующее правило ограничивает **частоту новых подключений** от одного IPv4: `limit rate over 15/second burst 40 packets` → `drop`.
4. Остальные пакеты проходят дальше по обработке nftables. `policy accept` в этой цепочке **не отменяет** возможные ограничения в других цепочках/таблицах firewall.

**Важно:** `ct count over 60` — это порог по количеству соединений, а не «60 подключений за секунду». Ограничение `15/second burst 40` — отдельная проверка частоты новых подключений. Доверенные IP освобождаются только от правил этой цепочки, а не от всего firewall.

### Доверенные IP

Набор `trusted4` имеет тип `ipv4_addr` и `timeout 6h`. В него можно добавлять адреса вручную. Также служба `xray-trust-watch.service` следит за логом доступа x-ui/Xray и добавляет IP, распознанные её скриптом как доверенные. **Точный критерий доверия следует смотреть в установленном скрипте watcher** — не следует считать, что любой успешный TCP-коннект автоматически делает IP доверенным.

Срок жизни записи — **6 часов с момента добавления**, если скрипт не обновляет её отдельно. Записи с тайм-аутом исчезают автоматически.

## Файлы и службы

| Объект | Путь / имя | Назначение |
|---|---|---|
| Основной файл правил | `/root/xray-guard.nft` | Определение таблицы, набора и цепочек nftables |
| Скрипт загрузки | `/usr/local/sbin/xray-guard-load.sh` | Загрузка правил с проверкой существования таблицы (для повторного запуска) |
| Служба загрузки | `xray-guard.service` | Однократная загрузка правил при старте (`oneshot`) |
| Служба доверенных IP | `xray-trust-watch.service` | Наблюдение за логом и добавление доверенных IP |
| Лог доступа Xray | `/usr/local/x-ui/access.log` | Источник событий для watcher |
| Конфигурация Xray | `/usr/local/x-ui/bin/config.json` | Генерируется x-ui; **не является файлом правил xray-guard** |

> Исполняемый скрипт watcher можно узнать через `systemctl cat xray-trust-watch.service` — путь к нему не следует угадывать.

## Установка с нуля (Debian, x-ui настраивается вручную)

Ниже — **воспроизводимый вариант установки** с полными текстами файлов. Он соответствует описанной схеме, но не является побайтовой копией уже установленных скриптов: для сверки действующей конфигурации используйте `systemctl cat` и `cat` на VPS. Все команды выполнять от `root` либо через `sudo`.

**Перед установкой:** обеспечьте доступ по SSH (на этом VPS — TCP/666) и, желательно, консоль провайдера. Установка не должна сбрасывать существующие таблицы nftables. Правила защищают только **IPv4 TCP/443**; IPv6 и UDP/443 не охватываются.

### 1. Подготовка пакетов и каталогов

```bash
apt update
apt install -y nftables python3
mkdir -p /usr/local/sbin /etc/systemd/system

# Резервная копия действующих правил firewall
nft list ruleset > "/root/nftables-before-xray-guard-$(date +%F-%H%M%S).nft"
```

Не запускайте `nft flush ruleset` и не включайте автоматически `nftables.service`: на этом сервере `/etc/nftables.conf` содержит `flush ruleset` и может затронуть другие правила.

### 2. Создание правил `/root/xray-guard.nft`

```bash
cat > /root/xray-guard.nft <<'NFT'
table inet xray_guard {
    set trusted4 {
        type ipv4_addr
        flags timeout
        timeout 6h
    }

    set unknown_connections4 {
        type ipv4_addr
        size 65535
        flags dynamic
    }

    chain input {
        type filter hook input priority -10; policy accept;
        meta nfproto ipv4 tcp dport 443 jump check443_v4
    }

    chain check443_v4 {
        counter
        ip saddr @trusted4 return
        ct state new add @unknown_connections4 { ip saddr ct count over 60 } counter drop
        ct state new meter new_connections4 size 65535 { ip saddr limit rate over 15/second burst 40 packets } counter drop
    }
}
NFT

nft -c -f /root/xray-guard.nft
```

Здесь `trusted4` — доверенные адреса на 6 часов, `ct count over 60` — лимит отслеживаемых соединений, `15/second burst 40` — лимит скорости новых соединений. Если `nft -c` выдаёт ошибку на конкретной версии nftables, **не применяйте файл**, пока синтаксис не исправлен.

### 3. Скрипт загрузки `/usr/local/sbin/xray-guard-load.sh`

```bash
cat > /usr/local/sbin/xray-guard-load.sh <<'SH'
#!/bin/sh
set -eu

# Не трогаем другие таблицы и не дублируем уже загруженную.
if nft list table inet xray_guard >/dev/null 2>&1; then
    echo 'xray_guard: table already exists; leaving it unchanged'
    exit 0
fi

nft -c -f /root/xray-guard.nft
nft -f /root/xray-guard.nft
echo 'xray_guard: rules loaded'
SH
chmod 755 /usr/local/sbin/xray-guard-load.sh
```

При повторном запуске этот скрипт **не перезаписывает** активную таблицу. Изменения файла `/root/xray-guard.nft` не вступят в силу автоматически, пока существующая таблица не будет заменена в отдельной контролируемой процедуре.

### 4. Скрипт доверенных IP `/usr/local/sbin/xray-trust-watch.py`

Этот пример доверяет IPv4-адресу **только после строки Xray access.log**, содержащей `accepted`, `inbound-443` и источник вида `from IP:PORT`. Это эвристика по формату журнала, **не криптографическая проверка VLESS-клиента**. Перед использованием проверьте реальные строки `/usr/local/x-ui/access.log`: если формат отличается, адаптируйте регулярное выражение. Скрипт не обрабатывает старые записи журнала — только новые строки после запуска.

```bash
cat > /usr/local/sbin/xray-trust-watch.py <<'PYWATCH'
#!/usr/bin/env python3
import ipaddress
import re
import subprocess
import sys
import time

LOG = '/usr/local/x-ui/access.log'
SOURCE = re.compile(r'\bfrom\s+(?:tcp:)?(\d{1,3}(?:\.\d{1,3}){3}):\d+\b')


def watch():
    # -n 0: не считать всю историю успешных соединений доверенной
    process = subprocess.Popen(
        ['tail', '-n', '0', '-F', LOG],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    try:
        for line in process.stdout:
            if 'accepted' not in line.lower() or 'inbound-443' not in line:
                continue
            match = SOURCE.search(line)
            if not match:
                continue
            address = match.group(1)
            try:
                ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError:
                continue
            # Добавление в nft через argv, без shell и подстановок.
            # Уже присутствующий IP не добавляем повторно; срок не обновляется.
            result = subprocess.run(
                ['nft', 'add', 'element', 'inet', 'xray_guard', 'trusted4',
                 '{ ' + address + ' timeout 6h }'],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print('trusted:', address, flush=True)
            elif 'File exists' not in result.stderr:
                print('nft error:', result.stderr.strip(), file=sys.stderr, flush=True)
    finally:
        process.terminate()


if __name__ == '__main__':
    while True:
        try:
            watch()
        except Exception as exc:
            print('watch error:', exc, file=sys.stderr, flush=True)
        time.sleep(3)
PYWATCH
chmod 755 /usr/local/sbin/xray-trust-watch.py
python3 -m py_compile /usr/local/sbin/xray-trust-watch.py
```

**Ограничение безопасности:** запись `accepted` в access.log не всегда означает, что клиент полностью аутентифицирован именно так, как ожидается. Не полагайтесь на watcher как на строгий механизм авторизации. Для более строгой схемы потребуется проверять реальный формат логов, привязку к VLESS-пользователю и устойчивость к поддельным строкам. Доверенные IP освобождаются от обоих ограничений `xray_guard` до истечения срока.

### 5. Службы systemd

```bash
cat > /etc/systemd/system/xray-guard.service <<'UNIT'
[Unit]
Description=Load xray-guard nftables rules for TCP/443
After=network-pre.target
Before=xray-trust-watch.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-guard-load.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/xray-trust-watch.service <<'UNIT'
[Unit]
Description=Trust IPv4 clients observed in Xray access log
Requires=xray-guard.service
After=xray-guard.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /usr/local/sbin/xray-trust-watch.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xray-guard.service
systemctl enable --now xray-trust-watch.service
```

Скрипт watcher читает журнал и изменяет nftables, поэтому запускается с правами root. Учитывайте это при изменении его кода и прав на файл лога.

### 6. Ручная настройка x-ui через интерфейс

**x-ui настраивается только через панель.** Не редактируйте `/usr/local/x-ui/bin/config.json` вручную: панель может перезаписать файл.

1. Откройте панель x-ui и убедитесь, что нужный VLESS inbound использует **TCP/443** и тег `inbound-443` (либо скорректируйте тег в watcher, если у вас он другой).
2. В настройках Xray через интерфейс x-ui **включите запись access.log** и укажите путь `/usr/local/x-ui/access.log` (названия разделов зависят от версии панели).
3. Сохраните настройки через панель и проверьте, что при успешном подключении клиента в `/usr/local/x-ui/access.log` появляются строки с `accepted`, `inbound-443` и `from IP:PORT`. Если формат другой, watcher из пункта 4 нужно адаптировать.
4. Отдельно убедитесь, что Xray действительно слушает TCP/443. Правила `xray_guard` сами по себе **не создают inbound** и не меняют маршрутизацию.

Не нужно добавлять в x-ui outbound или routing rule ради `xray_guard`: фильтрация происходит в ядре Linux **до обработки подключения Xray**. SOCKS/sing-box и правила маршрутизации сайтов — отдельная конфигурация.

### 7. Проверка установки

```bash
systemctl status xray-guard.service xray-trust-watch.service --no-pager
nft -a list table inet xray_guard
ss -lntp '( sport = :443 )'
tail -n 20 /usr/local/x-ui/access.log
journalctl -u xray-trust-watch.service -n 30 --no-pager

# После успешного подключения VLESS-клиента:
nft list set inet xray_guard trusted4
```

Если набор `trusted4` пуст, сначала проверьте **формат access.log**, а не ослабляйте ограничения firewall. Если нужен временный ручной доступ, добавьте свой IPv4 командой из раздела «Добавление и удаление доверенных IP».

### 8. Удаление установки (без изменения других таблиц)

**Осторожно:** удаление защиты снимет ограничения на TCP/443. Не удаляйте таблицу, если в неё позднее добавлены сторонние правила.

```bash
systemctl disable --now xray-trust-watch.service xray-guard.service
nft delete table inet xray_guard
rm -f /etc/systemd/system/xray-trust-watch.service \
      /etc/systemd/system/xray-guard.service \
      /usr/local/sbin/xray-trust-watch.py \
      /usr/local/sbin/xray-guard-load.sh \
      /root/xray-guard.nft
systemctl daemon-reload
```

## Шпаргалка администратора: управление, логи и статистика

Этот раздел можно использовать **каждый день после установки**, не перечитывая инструкцию. Все команды запускаются на VPS от `root` (или с `sudo`). Они **не меняют конфигурацию x-ui**.

### Состояние защиты за 10 секунд

```bash
# Статус двух служб (загрузчик правил и watcher доверенных IP)
systemctl status xray-guard.service xray-trust-watch.service --no-pager

# Загружена ли защита TCP/443
nft list table inet xray_guard

# Какие порты слушаются
ss -lntp | grep -E ':(443|666)\b'

# Какие службы включены в автозапуск
systemctl is-enabled xray-guard.service xray-trust-watch.service
```

`xray-guard.service` — одноразовая служба (`oneshot`): успешное выполнение и наличие таблицы важнее, чем надпись `active`/`inactive` после завершения.

### Управление сервисами

```bash
# Запуск / остановка / перезапуск watcher (отслеживание доверенных IP)
systemctl start xray-trust-watch.service
systemctl stop xray-trust-watch.service
systemctl restart xray-trust-watch.service

# Запуск загрузчика правил; существующая таблица не пересоздаётся
systemctl start xray-guard.service

# Включить автозапуск обоих сервисов
systemctl enable xray-guard.service xray-trust-watch.service

# Отключить автозапуск (НЕ удаляет уже загруженные правила)
systemctl disable xray-guard.service xray-trust-watch.service

# Проверить коды завершения и реальные команды из unit-файлов
systemctl show xray-guard.service -p Result -p ExecMainStatus
systemctl cat xray-guard.service xray-trust-watch.service

# Перечитать изменённые unit-файлы
systemctl daemon-reload
```

**Остановка watcher не отключает фильтр:** правила nftables продолжают работать, но новые доверенные IP больше не добавляются автоматически. **Остановка `xray-guard.service` не обязательно удаляет уже загруженную таблицу**. Не используйте `nft flush ruleset` для отключения одной защиты.

### Логи: загрузчик, watcher и Xray

```bash
# Последние 100 записей обоих сервисов
journalctl -u xray-guard.service -u xray-trust-watch.service -n 100 --no-pager

# Только загрузчик правил с текущей загрузки
journalctl -b -u xray-guard.service --no-pager

# Только watcher с текущей загрузки
journalctl -b -u xray-trust-watch.service --no-pager

# Следить за добавлением доверенных IP в реальном времени
journalctl -fu xray-trust-watch.service

# Ошибки watcher за последние 24 часа
journalctl -u xray-trust-watch.service --since '24 hours ago' -p warning --no-pager

# Логи x-ui (имя службы зависит от установленной версии)
journalctl -u x-ui -n 100 --no-pager

# Последние 100 строк access.log Xray
tail -n 100 /usr/local/x-ui/access.log

# Следить за подключениями Xray в реальном времени
tail -F /usr/local/x-ui/access.log

# Сколько строк добавилось в access.log за всё время существования файла
wc -l /usr/local/x-ui/access.log
```

Если лог Xray отключён в x-ui, `access.log` может не обновляться; включите access log **через веб-интерфейс x-ui**. Количество строк лога — не количество уникальных клиентов. Логи nftables по каждому отброшенному IP в текущей конфигурации **не ведутся**: для этого понадобилось бы отдельное правило `log` с ограничением частоты.

### Статистика nftables: пропуски, блокировки, IP

```bash
# Все правила защиты с пакетными/байтовыми счётчиками и handle
nft -a list table inet xray_guard

# Только цепочка проверки TCP/443: здесь видно counters и drop
nft -a list chain inet xray_guard check443_v4

# Автоматическое обновление счётчиков каждые 2 секунды
watch -n 2 'nft -a list chain inet xray_guard check443_v4'

# Доверенные IPv4, в том числе оставшееся время действия
nft list set inet xray_guard trusted4

# Набор, используемый лимитом числа соединений
nft list set inet xray_guard unknown_connections4

# Текущие счётчики соединений ядра (при наличии conntrack)
conntrack -S

# Заполненность таблицы conntrack
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max

# Текущие TCP-соединения с локальным портом 443 (моментальный снимок)
ss -tn state established '( sport = :443 )'

# Сколько таких TCP-соединений прямо сейчас
ss -Htn state established '( sport = :443 )' | wc -l
```

**Интерпретация:** `counter` в начале `check443_v4` считает проходящие через цепочку пакеты; `counter drop` у каждого лимита — отброшенные **пакеты**, не уникальные адреса и не число пользователей. Разница между значениями счётчиков за период показывает активность за этот период. При пересоздании таблицы и перезагрузке счётчики могут сбрасываться. Набор `unknown_connections4` — не бан-лист.

### Доверенные IP: добавить, посмотреть, удалить

```bash
# Посмотреть действующий белый список
nft list set inet xray_guard trusted4

# Вручную доверить IP на 6 часов (замените адрес своим)
nft add element inet xray_guard trusted4 '{ 203.0.113.10 timeout 6h }'

# Удалить IP из белого списка
nft delete element inet xray_guard trusted4 '{ 203.0.113.10 }'

# Посмотреть, какие адреса реально попали в набор
nft -a list set inet xray_guard trusted4
```

Адрес `203.0.113.10` приведён как **пример**. Watcher может добавить IP снова при следующем подходящем событии в access.log.

### Изменение правил и диагностика после перезагрузки

```bash
# Проверить синтаксис файла БЕЗ применения
nft -c -f /root/xray-guard.nft

# Посмотреть фактический код загрузчика и watcher
cat /usr/local/sbin/xray-guard-load.sh
systemctl cat xray-trust-watch.service

# Создать резервную копию всех активных правил
nft list ruleset > "/root/nftables-backup-$(date +%F-%H%M%S).nft"

# После перезагрузки: убедиться, что защита загружена
systemctl is-enabled xray-guard.service xray-trust-watch.service
nft list table inet xray_guard
journalctl -b -u xray-guard.service -u xray-trust-watch.service --no-pager
```

**Важно при редактировании `/root/xray-guard.nft`:** существующий загрузчик проверяет наличие таблицы и может **не обновить** активные правила. Для изменения порогов сначала делайте резервную копию и планируйте адресное изменение nftables либо контролируемое пересоздание **только** таблицы `inet xray_guard` при наличии рабочего SSH/консоли. `nft flush ruleset` запрещён как штатный способ обновления: он затрагивает другие правила сервера, включая доступ к SSH и панели.

---

## Быстрая проверка состояния

```bash
# Службы
systemctl status xray-guard.service --no-pager
systemctl status xray-trust-watch.service --no-pager

# Включены ли при загрузке
systemctl is-enabled xray-guard.service xray-trust-watch.service

# Существует ли таблица и какие правила загружены
nft list table inet xray_guard

# Слушает ли Xray порт 443
ss -lntp '( sport = :443 )'
```

**Особенность `oneshot`:** состояние `inactive (dead)` после успешного завершения может быть нормальным, если у службы нет `RemainAfterExit=yes`. Проверяйте `systemctl status`, журнал и наличие таблицы nftables; не делайте вывод об ошибке только по слову `inactive`.

## Статистика и диагностика nftables

```bash
# Все правила защиты, включая счётчики и текущие IP в наборах
nft -a list table inet xray_guard

# Только цепочка проверок на 443
nft -a list chain inet xray_guard check443_v4

# Список доверенных IPv4 и оставшееся время жизни (если отображается)
nft list set inet xray_guard trusted4

# Список адресов, участвующих в ограничении числа соединений
nft list set inet xray_guard unknown_connections4

# Правила и счётчики с отметками времени — наблюдение раз в 2 секунды
watch -n 2 'nft -a list chain inet xray_guard check443_v4'

# Общая статистика conntrack (если установлен пакет conntrack)
conntrack -S

# Количество записей conntrack в системе (если доступен sysctl)
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
```

**Как читать счётчики:** `counter packets` и `bytes` относятся к пакетам, попавшим в конкретное правило. Счётчик рядом с `drop` позволяет оценивать число отброшенных пакетов, **но не число уникальных IP и не число отдельных TCP-сеансов**. Счётчики обычно сбрасываются при удалении/пересоздании правил и при перезагрузке.

Набор `unknown_connections4` используется механизмом ограничения числа соединений; **его содержимое нельзя интерпретировать как постоянный чёрный список**.

## Журналы

```bash
# Последние сообщения загрузчика правил
journalctl -u xray-guard.service -n 100 --no-pager

# Последние сообщения watcher
journalctl -u xray-trust-watch.service -n 100 --no-pager

# Следить за watcher в реальном времени
journalctl -u xray-trust-watch.service -f

# Журналы с текущей загрузки
journalctl -b -u xray-guard.service -u xray-trust-watch.service --no-pager

# Последние события из access.log
tail -n 100 /usr/local/x-ui/access.log

# Следить за access.log
tail -f /usr/local/x-ui/access.log
```

Сам nftables **не записывает каждый `drop` в журнал**, если в правиле нет отдельного действия `log`. В данной схеме предусмотрены счётчики, но не гарантируется поимённый журнал всех отклонённых IP.

## Управление службами

```bash
# Перезапустить наблюдение за доверенными IP
systemctl restart xray-trust-watch.service

# Остановить / запустить watcher
systemctl stop xray-trust-watch.service
systemctl start xray-trust-watch.service

# Включить автозапуск
systemctl enable xray-guard.service xray-trust-watch.service

# Просмотреть unit-файлы и фактические команды запуска
systemctl cat xray-guard.service
systemctl cat xray-trust-watch.service

# Проверить результат последнего запуска загрузчика
systemctl show xray-guard.service -p Result -p ExecMainStatus
```

### Перезагрузка правил

Сначала **проверьте синтаксис**, затем используйте установленный загрузчик:

```bash
nft -c -f /root/xray-guard.nft
/usr/local/sbin/xray-guard-load.sh
nft -a list table inet xray_guard
```

**Внимание:** загрузчик проверяет существование таблицы и не обязан обновлять уже загруженные правила. Если вы **изменили** `/root/xray-guard.nft`, повторный запуск загрузчика может оставить старую версию активной. Не применяйте `flush ruleset`: это удалит **все** таблицы firewall, включая не относящиеся к `xray-guard`.

Для изменения активных правил предпочтительны адресные команды `nft` или отдельная процедура обслуживания с резервной копией и доступом через SSH/консоль.

## Добавление и удаление доверенных IP

```bash
# Добавить IPv4 на 6 часов (замените пример своим адресом)
nft add element inet xray_guard trusted4 '{ 203.0.113.10 timeout 6h }'

# Проверить наличие адреса
nft list set inet xray_guard trusted4

# Удалить доверенный адрес
nft delete element inet xray_guard trusted4 '{ 203.0.113.10 }'
```

`203.0.113.10` — документационный пример, **не реальный адрес пользователя**. Не добавляйте широкие сети без необходимости. Доверие может быть временным: запись автоматически истечёт через 6 часов, если не обновлена.

## Резервная копия и восстановление

```bash
# Сохранить текущую конфигурацию nftables (ВСЕ таблицы)
nft list ruleset > /root/nftables-backup-$(date +%F-%H%M%S).nft

# Отдельно сохранить только правила xray-guard
nft list table inet xray_guard > /root/xray-guard-active-$(date +%F-%H%M%S).nft

# Резервная копия исходного файла правил
cp -a /root/xray-guard.nft /root/xray-guard.nft.bak.$(date +%F-%H%M%S)
```

Не восстанавливайте полный ruleset вслепую: на сервере могут существовать правила SSH, панели x-ui и другие таблицы. Прежде чем удалять или заменять таблицу `xray_guard`, убедитесь, что у вас есть работающий SSH-доступ (на данном сервере SSH использует **TCP/666**) или консоль провайдера.

## Автозапуск и важные особенности

- `xray-guard.service` и `xray-trust-watch.service` настроены для запуска через systemd.
- Загрузчик `xray-guard-load.sh` должен предотвращать повторное создание уже существующей таблицы.
- Служба `nftables.service` на сервере была отключена, поскольку `/etc/nftables.conf` содержит `flush ruleset`. **Не включайте её без проверки**, иначе она может стереть правила, созданные другими службами.
- На сервере есть и другие таблицы/цепочки firewall, в том числе связанные с доступом к панели x-ui. `xray-guard` защищает только IPv4 TCP/443 и не гарантирует сохранение прочих правил после перезагрузки.
- Текущие правила не покрывают IPv6 TCP/443. Если Xray слушает IPv6 и сервер имеет публичный IPv6, это следует проверить отдельно.
- Содержимое `trusted4` динамическое и не обязано переживать перезагрузку; watcher добавляет адреса на основании новых событий из журнала.

## Быстрый чек-лист после перезагрузки VPS

```bash
systemctl is-enabled xray-guard.service xray-trust-watch.service
systemctl status xray-guard.service xray-trust-watch.service --no-pager
nft -a list table inet xray_guard
ss -lntp '( sport = :443 or sport = :666 )'
journalctl -b -u xray-guard.service -u xray-trust-watch.service --no-pager
```

Если отсутствует таблица `inet xray_guard`, сначала изучите `journalctl -u xray-guard.service -b`, затем проверьте исходный файл `/root/xray-guard.nft` и загрузчик. Если таблица есть, но доверенные IP не появляются, проверяйте watcher и доступность `/usr/local/x-ui/access.log`.
