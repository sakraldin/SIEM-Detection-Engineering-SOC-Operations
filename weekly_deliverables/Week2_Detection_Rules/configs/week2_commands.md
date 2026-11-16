# Commands Used in Week 2

Each command is listed with the machine where it was run.

## Validate and restart rules (wazuh-server)

    sudo nano /var/ossec/etc/rules/local_rules.xml
    sudo /var/ossec/bin/wazuh-analysisd -t
    sudo systemctl restart wazuh-manager
    sudo systemctl status wazuh-manager
    sudo tail -n 15 /var/ossec/logs/ossec.log
    sudo cat /var/ossec/etc/rules/local_rules.xml

`analysisd -t` must show only the INFO line about rule tree memory. Any WARNING (for example about a deprecated option) means the option is ignored or invalid.

## Backups and edits (wazuh-server)

    sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
    sudo sed -i 's|<rule id="100010" level="10" frequency="6" timeframe="120">|<rule id="100010" level="10" frequency="6" timeframe="120" ignore="120">|' /var/ossec/etc/rules/local_rules.xml
    sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak2
    sudo sed -i 's#COMMAND=\\S\*(scp#COMMAND=\\S*/(scp#' /var/ossec/etc/rules/local_rules.xml
    sudo grep -n 'COMMAND=' /var/ossec/etc/rules/local_rules.xml

## FIM configuration (ubuntu-victim)

    sudo grep -n "directories" /var/ossec/etc/ossec.conf
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    sudo sed -i '114s|<directories>|<directories check_all="yes" realtime="yes">|' /var/ossec/etc/ossec.conf
    sudo systemctl restart wazuh-agent
    sudo systemctl status wazuh-agent

## Test commands (endpoints)

| Rule | Command | Machine |
|---|---|---|
| 100010 | ssh -o NumberOfPasswordPrompts=1 victim@192.168.56.111 (wrong password) | Kali |
| 100010 | for i in $(seq 1 40); do echo "wrong$i"; done > /tmp/wl.txt | Kali |
| 100010 | hydra -l victim -P /tmp/wl.txt -t 1 ssh://192.168.56.111 | Kali |
| 100012 | ssh victim@192.168.56.111, then ssh victim2@192.168.56.113 | Kali |
| 100013 | sudo adduser backdoor1 / sudo adduser fimtest | ubuntu-victim |
| 100013 (negative) | sudo usermod -c "test comment" victim, then sudo usermod -c "" victim | ubuntu-victim |
| 100014 | sudo scp /etc/hostname victim@192.168.56.111:/tmp/ | ubuntu-victim2 |
| 100014 | sudo curl --version | ubuntu-victim, ubuntu-victim2 |
| 100014 (negative) | curl --version (no sudo), sudo sync | ubuntu-victim |
| 100015 | sudo su - | ubuntu-victim |
| 100015 (negative) | sudo ls | ubuntu-victim |
| 100016 | sudo adduser fimtest | ubuntu-victim |
| 100016 (negative) | sudo touch /etc/test_fim_neg2 | ubuntu-victim |

## Cleanup (ubuntu-victim)

    sudo deluser --remove-home fimtest
    sudo deluser --remove-home backdoor1
    sudo deluser --remove-home testuser1
    sudo rm /etc/test_fim_neg2

## Dashboard queries (Threat Hunting, Events, last 24 hours)

    rule.id: 100010
    rule.id: 100011
    rule.id: 100012
    rule.id: 100013
    rule.id: 100014
    rule.id: 100015
    rule.id: 100016
    rule.id: 5715
    rule.id: 5760
    rule.groups: syscheck

## Shutdown for snapshots (each VM)

    sudo poweroff