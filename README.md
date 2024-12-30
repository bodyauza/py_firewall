# Брандмауэр на Python. 

## Установка необходимых пакетов

Для установки необходимых пакетов выполните следующие команды:

```bash
sudo apt-get install python3-pip
sudo apt-get install iptables-dev libnetfilter-queue-dev
pip3 install NetfilterQueue
```

## Настройка iptables

Настройте iptables для перенаправления пакетов в очередь nfqueue. Эти команды перенаправляют все входящие и исходящие пакеты в очередь номер 1:

```bash
sudo iptables -A INPUT -j NFQUEUE --queue-num 1
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1
```