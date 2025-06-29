# myRPC: Remote Procedure Call System

## Описание проекта
**myRPC** - это система для удалённого выполнения команд на сервере через JSON-протокол. Состоит из двух компонентов:
- **myRPC-server** - сервер, принимающий команды и возвращающий результат
- **myRPC-client** - клиент, отправляющий команды на сервер

**Основные возможности**:
- Поддержка TCP (stream) и UDP (dgram) сокетов
- Аутентификация пользователей через файл users.conf
- Логирование через libmysyslog (записи в /var/log/syslog)
- Простая JSON-сериализация запросов и ответов

## Установка

### 1. Сборка из исходников
```
git clone https://github.com/Sobol1488/myRPC.git
cd myRPC
make all           # Сборка клиента, сервера и библиотеки
sudo make install  # Установка в /usr/local/bin/
```

### 2. Запуск системы (сервер и клиент)
Запуск сервера
```
Ручной запуск
./myRPC-server
```
```
Как демон (systemd)
sudo systemctl start myRPC-server
sudo systemctl enable myRPC-server  # Автозагрузка
```
Запуск клиента
```
myRPC-client -h <IP> -p <PORT> -s -c "<COMMAND>"
```
### 3. Параметры клиента
| Флаг | Описание |	Пример |
| --- | --- | --- |
| -h, --host |	IP сервера |	-h 127.0.0.1 |
| -p, --port |	Порт сервера |	-p 1234 |
| -s, --stream |	Использовать TCP (по умолчанию) |	-s |
| -d, --dgram |	Использовать UDP |	-d |
| -c, --command |	Команда для выполнения |	-c "ls /" |
| --help |	Справка |	--help |
