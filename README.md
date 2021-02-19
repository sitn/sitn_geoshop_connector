# Connecteur EXTRACT pour le geoshop SITN

Ce connecteur, développé par la société [Arx iT](https://www.arxit.com/), permet de traiter les commandes du [géoshop SITN](https://sitn.ne.ch/geoshop2) dans [EXTRACT](https://github.com/asit-asso/extract).

# Guide de démarrage pour développeurs

Les instructions ci-dessous décrivent comment importer dans NetBeans le code source du plugin Geoshop et comment le compiler.
Le code source a été compilé avec NetBeans 8.1 dans un environnement Linux. **Il n'a pas été testé et compilé sur Eclipse ni sur un environnement Windows.**

Le logiciel NetBeans 8.1 version Linux est requis, il est téléchargeable sur la page suivante : https://netbeans.org/community/releases/81/

Il faut également installer une nouvelle version de maven et la référencer dans les options de netbeans (Java > Maven) car les dépôts maven n'acceptent plus les requêtes non-https.

## Importer le code dans NetBeans

1. Télécharger le zip correspondant au code source. Le zip doit contenir les deux dossiers **connectors** et **plugin-interface**

2. Décompresser le fichier zip dans un dossier ; par exemple /home/neuchatel/projects/geoshop. Ce dossier contiendra donc les sous-dossiers **connectors** et **plugin-interface**

3. Ouvrir NetBeans

4. Créer un nouveau groupe de projet 
    - Depuis la barre de menu, choisir File -> Project Groups
    - Cliquer sur le bouton "New Groups
    - Donner un groupe au groupe
    - Cocher l'option "Folder of Projects". A l'aide du bouton "Browser", sélectionner le dossier dans lequel le code a été placé (ex : /home/neuchatel/projects/geoshop)
    - Cliquer sur "Create Group"
    - Les deux projets "extract-connector-geoshop" et "extract-interface" apparaissent dans la fenêtre de navigation à gauche


## Compiler le code source

1. Vérifier les propriétés de chacun des deux projets, en accédant aux propriétés (Clic droit -> Properties)
    - Catégorie General : modifier si besoin la version  
    - Categorie Build>Compile : choisir la plateforme JAVA JDK 1.7

2.  Compiler les deux projets extract-interface et extract-connector-geoshop :
    - Depuis l'onglet files
    - clic droit -> Build With Dependencies (les tests unitaires sont exécutés en même temps)
    - Le fichier jar compilé est généré dans un sous-répertoire **target** du dossier **extract-connector-geoshop** (ex : /home/neuchatel/projects/geoshop/target/extract-connector-geoshop-1.2-RELEASE.jar)

3. Le jar compilé peut ensuite être importé dans l'application extract comme détaillé dans la documentation https://projets.asitvd.ch/attachments/download/9289/Extract_ManuelExploitation_v1.2.0.pdf
