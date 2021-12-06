# -----------------      -Exercice1 GNS3 OpenScap OSSEC12-      ----------------

# Tâche :

Depuis la machine "controler" (192.168.122.216, CentOS 7) il faut installer l'outil OpenScap pour ensuite via le protocole SSH (connexion sécurisée réalisé avec une clé Publique RSA) analyser la machine "srv2" (192.168.122.10, CentOS 7) en utilisant comme base ANSSI.
Lorsque l'analyse est terminée il faut apporter le correctif pour une vulnérabilité (fail) en utilisant ansible.

# 1 Création des variables :

> Pour se faire j'ai enregistré les variables dans un fichier scripte pour qu'en cas de plantage ou redémarrage de la machine "controler" j'execute le scripte et gagne du temps 

=>  ./Varaibles.sh

  !/bin/sh                                                                      
                                                                                
  target="srv2"                                                                  
  type="$target-bp28m-before"                                                    
  profile="xccdf_org.ssgproject.content_profile_anssi_nt28_minimal"              
  cpe_dict="/usr/share/xml/scap/ssg/content/ssg-rhel7-cpe-dictionary.xml"        
  data_stream="/usr/share/xml/scap/ssg/content/ssg-rhel7-ds-1.2.xml"                                                    
  rule1="xccdf_org.ssgproject.content_rule_ensure_gpgcheck_local_packages"       


# 2 Connexion ssh avec clef RSA vers machine cible « srv2 » :

Le protocole ssh combiné avec une clef RSA va nous permettre de nous connecter à la machine cible et exécuter les analyses sans devoir s’authentifier avec un mot de passe.(sauf pour la 1er connexion)

> Commande pour la création de la clef RSA 

=> ssh-keygen -b 4096 -t rsa -f $HOME/.ssh/id_rsa -q -N ""
 
Copie de la clef publique vers la machine cible "srv2" 

=> ssh-copy-id $target

> Installation du module de sécurité SSG sur la machine cible "srv2"

=> ssh $target "yum -y install scap-security-guide"

# 3 Installation des packages OpenScap + SSG sur le contrôleur :

=> curl -L https://git.io/JMiO5 | bash -x

# 4 Exécution de la commande pour effectuer l’analyse sur la machine    cible « srv2 » :

> La commande de l’outil Openscap ci-dessous va lancer une analyse via ssh sur la machine cible « srv2 » en se basant sur les critères de sécurité ANSSI pour ensuite générer de fichier de rapport en xml et html qui seront nommé via la variable $type en « srv2-bp28m-before ».

=>  oscap-ssh --sudo root@$target 22 xccdf eval --fetch-remote-resource --profile $profile --results $type-results.xml --report $type-report.html --oval-results --cpe $cpe_dict $data_stream

> Vérification que les fichiers ont bien été généré après l’analyse.

=> ls -l srv*

# 5 Exécution de la commande pour générer un fichier de guide de configuration :

> Ce fichier permet de donner les solutions pour résoudre les mauvaises configurations et les vulnérabilités.

=>  oscap xccdf generate guide --profile $profile --output $type-guide.html $type-results.xml

# 6 Exécution de la commande python pour générer l’accès au guide.html sur le web :

> Comme le service firewalld est arrêté tous les ports sont ouvert et donc la commande pour ouvrir le port 8080 n’est pas nécessaire, mais bien sur ce n’est pas sécure.

=>  python3 -m http.server 8080

> Sur un navigateur il est possible maintenant d’accéder à la page web sur l’adresse :192.168.122.216 :8080

# 7 Scanne de l’état d’une règle sur la machine cible « srv2 » :

> Dans cette étape nous allons seulement vérifier si le statut de la règle défini dans la variable $rule1.

=>  oscap-ssh --sudo root@$target 22 xccdf eval \
    --fetch-remote-resource \
    --profile $profile \
    --results rule1-$type-results.xml \
    --report rule1-$type-report.html \
    --oval-results \
    --cpe $cpe_dict \
    --rule $rule1 \
    $data_stream

# 8 récupération dans une variable du fix ansible sur base de l'ID de la règle de vulnérabilité :

> Nous allons charger le fix ansible dans une variable nommée $result_id, pour cela nous avons besoin de l’id de la règle qui est stocké dans la variable $rule1 et exécuter la commande suivante :

=>  result_id=$(oscap info rule1-$type-results.xml | grep 'Result ID' | sed 's/[[:blank:]]Result ID: //')
    oscap xccdf generate fix \
    --fix-type ansible \
    --output rule1-$type-playbook.yml \
    --profile $profile \
    --result-id $result_id \
    rule1-$type-results.xml
# 9 résolution de la vulnérabilité avec ansible :
  
> Execution de la commande de résolution de la vulnérabilité

=>  ansible-playbook -i "$target," rule1-$type-playbook.yml  

> Pour que la résolution soit effective nous allons redémarrer la cible « srv2 »

=>  ansible all -i "$target," -m reboot

# 10 Validation de la mise en conformité

> Nous pouvons maintenant vérifier avec la commande ci-dessous si la vulnérabilité a été résolu, cette commande va générer un nouveau fichier qu'on nommera "std-after" pour ce faire nous allons remplacer le contenu de notre variable $type

=>  type="std-after"
    profile="xccdf_org.ssgproject.content_profile_anssi_nt28_minimal"
    oscap-ssh --sudo root@$target 22 xccdf eval \
    --fetch-remote-resource \
    --profile $profile \
    --results rule1-$type-results.xml \
    --report rule1-$type-report.html \
    --oval-results \
    --cpe $cpe_dict \
    --rule $rule1 \
    $data_stream
