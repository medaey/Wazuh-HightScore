#!/bin/bash

# Variables de contrôle
# Utilisez "true" pour activer et "false" pour désactiver les modules
ENABLE_CRAMFS=false
ENABLE_SQUASHFS=false
ENABLE_HFS=false
ENABLE_HFSPLUS=false
ENABLE_UDF=false
ENABLE_JFFS2=false
ENABLE_FREEVXFS=false

# Dossiers de configuration
CONFIG_DIR="/etc/modprobe.d"

# Fonctions pour activer les systèmes de fichiers
enable_module() {
    local module=$1
    local config_file="$CONFIG_DIR/${module}.conf"
    
    if [ -f "$config_file" ]; then
        echo "Suppression du fichier de désactivation de $module."
        sudo rm -f "$config_file"
    fi
    echo "Rechargement des modules du noyau pour $module..."
    sudo modprobe $module
    echo "Le support de $module a été activé."
}

# Fonctions pour désactiver les systèmes de fichiers
disable_module() {
    local module=$1
    local config_file="$CONFIG_DIR/${module}.conf"
    
    echo "Désactivation du support de $module..."
    echo "install $module /bin/true" | sudo tee "$config_file" > /dev/null
    echo "Déchargement du module $module, s'il est chargé..."
    if lsmod | grep -q "^${module}"; then
        sudo /sbin/rmmod $module
    else
        echo "Le module $module n'était pas chargé."
    fi
    echo "Ajout de $module à la liste noire..."
    echo "blacklist $module" | sudo tee -a /etc/modprobe.d/blacklist.conf > /dev/null
    echo "Le support de $module a été désactivé."
}

# Activer ou désactiver les modules en fonction des variables de contrôle
manage_module() {
    local module=$1
    local enable=$2
    
    if [ "$enable" = true ]; then
        enable_module $module
    else
        disable_module $module
    fi
}

# Gestion des modules
manage_module "cramfs" $ENABLE_CRAMFS
manage_module "squashfs" $ENABLE_SQUASHFS
manage_module "hfs" $ENABLE_HFS
manage_module "hfsplus" $ENABLE_HFSPLUS
manage_module "udf" $ENABLE_UDF
manage_module "jffs2" $ENABLE_JFFS2
manage_module "freevxfs" $ENABLE_FREEVXFS

echo "Configuration terminée."
