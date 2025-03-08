Sniffer Réseau avec Détection Anormale  

Introduction  
Ce projet est un sniffer réseau avancé en Python, capable de :  
• Capturer le trafic DNS en temps réel sur une interface réseau donnée.  
• Filtrer et analyser les requêtes DNS (Domain Name System).  
• Détecter une activité suspecte basée sur un critère personnalisé :  
   - Plus de 20 requêtes DNS vers le même domaine en 10 secondes.  
   - Connexion à des domaines suspects (ex: Dark Web).  
   - Requêtes vers des URL sensibles contenant des mots-clés comme "admin", "secret", etc.  
• Enregistrer les résultats dans un fichier `traffic_log.txt`.  


✓ Structure du projet  
Le projet est organisé comme suit :  
/sniffer-reseau
│── sniffer.py          # Script principal
│── requirements.txt    # Liste des dépendances (ex: Scapy)
│── traffic_log.txt     # Fichier de log des requêtes capturées
│── README.md           # Documentation détaillée

✓ Installation des dépendances 
code permettant l'installation scapy
pip install -r requirements.txt

✓ Démarrer le sniffer réseau
Lance le sniffer avec les droits administrateurs pour capturer les paquets :
sudo python3 sniffer.py eth0

Remplace eth0 par wlan0 si tu utilises le Wi-Fi.
Le script affiche en temps réel les requêtes interceptées et leur statut (NORMAL / ANORMAL).

✓ Explication de la Détection d’Anomalies
Critères de détection mis en place

Le sniffer surveille les requêtes DNS en temps réel et applique les règles suivantes :

  • Détection d'un trop grand nombre de requêtes

Si une même adresse IP fait plus de 20 requêtes DNS vers un même domaine en 10 secondes, c’est considéré comme anormal.
Ex : Un script malveillant ou une attaque DDoS qui bombarde Google avec des requêtes DNS.
   •Détection de connexion à un domaine suspect
Certains domaines comme darkwebmarket.com ou hackingtool.com sont considérés comme dangereux.
Une alerte est enregistrée dans traffic_log.txt si une requête vers ces sites est détectée.
    •Détection de mots-clés sensibles

Si une requête contient un mot comme admin, login, secret, elle est signalée.

✓ Tests et Validation
Tester le sniffer avec des requêtes DNS
1- Lancer le sniffer sur ton interface réseau
sudo python3 sniffer.py eth0

2- Effectuer des requêtes DNS manuelles
Dans un terminal :
nslookup google.com
nslookup facebook.com
nslookup darkwebmarket.com

Regarde si le fichier traffic_log.txt capture bien ces requêtes.

Conclusion
Ce projet offre un sniffer réseau complet permettant d’analyser le trafic DNS et d’identifier les comportements suspects.

 Objectifs atteints :
- Capture du trafic DNS
- Détection d’anomalies et alertes
- Enregistrement des logs
- Documentation complète
