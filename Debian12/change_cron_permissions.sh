#!/bin/bash

# Script pour modifier les permissions des fichiers et répertoires cron

# Modifier les permissions de /etc/crontab
echo "Modification des permissions de /etc/crontab..."
sudo chmod 600 /etc/crontab
sudo chown root:root /etc/crontab

# Modifier les permissions de /etc/cron.hourly
echo "Modification des permissions de /etc/cron.hourly..."
sudo chmod 700 /etc/cron.hourly
sudo chown root:root /etc/cron.hourly

# Modifier les permissions de /etc/cron.daily
echo "Modification des permissions de /etc/cron.daily..."
sudo chmod 700 /etc/cron.daily
sudo chown root:root /etc/cron.daily

# Modifier les permissions de /etc/cron.weekly
echo "Modification des permissions de /etc/cron.weekly..."
sudo chmod 700 /etc/cron.weekly
sudo chown root:root /etc/cron.weekly

# Modifier les permissions de /etc/cron.monthly
echo "Modification des permissions de /etc/cron.monthly..."
sudo chmod 700 /etc/cron.monthly
sudo chown root:root /etc/cron.monthly

# Modifier les permissions de /etc/cron.d
echo "Modification des permissions de /etc/cron.d..."
sudo chmod 700 /etc/cron.d
sudo chown root:root /etc/cron.d

echo "Permissions modifiées avec succès."
