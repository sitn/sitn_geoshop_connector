# Connecteur EXTRACT pour le geoshop SITN

Ce connecteur, développé par la société [Arx iT](https://www.arxit.com/), permet de traiter les commandes du [géoshop SITN](https://sitn.ne.ch/geoshop2) dans [EXTRACT](https://github.com/asit-asso/extract).

# Guide de démarrage pour développeurs

## Prérequis

 * Eclipse
 * JDK 7 https://jdk.java.net/java-se-ri/7

## Importer le projet dans Eclipse

1. Forker et cloner ce dépôt

2. Ouvrir Eclipse

3. File > Import...

4. Ouvrir *Maven*, sélectionner *Existing Maven Project*

5. Dans *Root Directory*, cliquer sur *Browse* et aller chercher le dossier racine précedemment cloné.

6. Cliquer sur Finish. Deux packages devraient être disponibles:

    - extract-connector-geoshop

    - extract-plugin-interface

7. Aller dans le menu Run > Run Configurations...

8. Dans la barre de gauche, dans Maven build, **pour chaque projet maven**:

    - Aller dans l'onglet JRE et choisir *JavaSE-1.7* en tant dans *Execution environment*
    - Cliquer sur Apply

## Compiler le code source

1. Vérifier les propriétés de chacun des deux projets, en éditant le pom.xml:
    - Catégorie General : modifier si besoin la version  
    - Categorie Build>Compile : choisir la plateforme JAVA JDK 1.7

2.  Compiler **d'abord** extract-interface puis extract-connector-geoshop :
    - Depuis *Package explorer*
    - clic droit -> *Run As* -> *Maven install*
    - Le fichier jar compilé est généré dans un sous-répertoire **target** du dossier **extract-connector-geoshop** (ex : /home/neuchatel/projects/geoshop/target/extract-connector-geoshop-1.2-RELEASE.jar)

3. Le jar compilé peut ensuite être importé dans l'application extract comme détaillé dans la documentation https://projets.asitvd.ch/attachments/download/9289/Extract_ManuelExploitation_v1.2.0.pdf
