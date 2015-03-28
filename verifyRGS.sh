#!/bin/sh
#deux scripts, 1. vérifier les certificats, 2. vérifier les CRL

mkdir verifyResults
for i in certificats/*.cer
do
    echo "****************************************************************************************************************************"
    echo $i
    echo "****************************************************************************************************************************"
    #essayer de trouver une chaine "Certificate:", si oui enregistrer, si non changer encodage
    openssl x509 -text -noout -in "$i" -inform PEM > "$i.txt"

    if grep "Certificate:" "$i.txt"
    then
    	cp "$i" "$i.pem"
        openssl x509 -text -noout -in "$i" -inform PEM > "$i.txt"
        openssl asn1parse -in "$i" -inform PEM > "$i.asn1.txt"
    else
    	openssl x509 -in "$i" -inform DER -out "$i.pem" -outform PEM
        openssl x509 -text -noout -in "$i" -inform DER > "$i.txt"
        openssl asn1parse -in "$i" -inform DER > "$i.asn1.txt"
    fi

    #Extraction du CN du porteur
    issuerCN=$(grep -A 1 "commonName" "$i.asn1.txt" | sed -n '2,2p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')
    subjectCN=$(grep -A 1 "commonName" "$i.asn1.txt" | sed -n '5,5p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')
    #serial=$(grep "Serial Number" $i.txt | sed 's/\(.*\)(\(.*\))/\2/')
    serial=$(grep -A 1 ":02" "$i.asn1.txt" | sed -n '2,2p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')

    #Renommer les fichiers: issuerCN - subjectCN
    filename=$(echo "$issuerCN - $subjectCN - $serial")
    mv "$i.pem" "verifyResults/$filename.pem"
    mv "$i.txt" "verifyResults/$filename.txt"
    mv "$i.asn1.txt" "verifyResults/$filename.asn1.txt"

    #Subject
    echo "---------------------------------------------------------------------------------------------------"
    echo "Identification du sujet"
    echo "L'attribut countryName doit être présent. Il doit être renseigné en lettres majuscules."
    echo "L'attribut organizationName doit être présent et doit contenir le nom officiel complet de l'entité."
    echo "Une instance de l'attribut organizationalUnitName doit être présente: <00002> <SIRET/SIREN>."
    echo "Si d'autres instances de l'attribut organizationalUnitName sont présentes, elles ne doivent pas commencer par 4 chiffres."
    echo "Certificat de personnes:"
    echo "    L'attribut commonName doit comporter le premier prénom suivi d'un espace, suivi du nom du porteur."
    echo "    il n'y a pas d'obligation à mentionner ces autres prénoms dans le certificat, mais s'ils le sont,"
    echo "    ils doivent l'être dans le même ordre que sur la pièce d'identité et séparés par une virgule"
    echo "    sans espace ni avant ni après la virgule."
    echo "    Pour les prénoms et noms composés, le tiret est utilisé comme élément séparateur."
    echo "    La distinction des cas d'homonymie au sein du domaine de l'AC peut se faire au travers de l'attribut commonName."
    echo "Certificats de machines:"
    echo "    L’attribut commonName doit être utilisé et doit contenir un nom significatif du service applicatif,"
    echo "    à l’exception des deux cas particuliers suivants:"
    echo "    - lorsqu’il s’agit d’un certificat serveur de type SSL/TLS, l’attribut commonName est facultatif."
    echo "      S’il est présent, il doit contenir un FQDN (Fully Qualified Domain Name) du serveur également présent dans l’extension SubjectAlternativeName."
    echo "      S’il est absent, l’extension SubjectAlternativeName doit être critique."
    echo "    - lorsqu’il s’agit d’un certificat de signature de code, l’attribut commonName est facultatif."
    echo "      S’il est présent, il ne doit pas contenir un FQDN."
    echo "Le DN doit être encodé en PRINTABLESTRING ou UTF8"
    echo "Référencement SGMAP - Vérifier l'encodage des champs (tout UTF8 sauf countryName PRINTABLESTRING)"
    echo "---------------------------------------------------------------------------------------------------"
    grep -A 1 "countryName" "verifyResults/$filename.asn1.txt" | sed -n '4,5p'
    grep -A 1 "organizationName" "verifyResults/$filename.asn1.txt" | sed -n '4,5p'
    grep -A 1 "organizationalUnitName" "verifyResults/$filename.asn1.txt" | sed -n '4,5p'
    grep -A 1 "commonName" "verifyResults/$filename.asn1.txt" | sed -n '4,5p'

    #Serial number
    echo "-----------------------------------------------------------------------------------------------------------"
    echo "[RGS 2.0] Le Serial Number doit être généré pour être unique. Il est recommandé que le Serial Number soit non prédictible. Les AC en service lors de la parution de la V2.0 du RGS qui ne respecteraient pas cette exigence doivent le faire lors du renouvellement de leur certificat."
    echo "-----------------------------------------------------------------------------------------------------------"
    grep "Serial Number" "verifyResults/$filename.txt"


    #Vérifier la version
    echo "-----------------------------------------"
    echo "Vérifier la version x509: version 3 (0x2)"
    echo "-----------------------------------------"
    grep "Version" "verifyResults/$filename.txt"

    #Vérifier Issuer
    echo "-----------------------------------------------"
    echo "Vérifier que l'émetteur est bien l'AC qualifiée"
    echo "-----------------------------------------------"
    #grep "Issuer:" "verifyResults/$filename.txt" | sed -e "s/Issuer: /%/g" | cut -d'%' -f2 #coupe ce qui est apres
    grep "Issuer:" "verifyResults/$filename.txt"

    #Vérifier algorithme de signature
    echo "----------------------------------"
    echo "Vérifier l'algorithme de signature"
    echo "----------------------------------"
    grep "Signature Algorithm" "verifyResults/$filename.txt" | sed -n '2,2p'

    #Validity
    echo "--------------------------------------------------------"
    echo "Vérifier la durée de vie (AC 10 ans, porteur 3 ans max.)"
    echo "--------------------------------------------------------"
    grep "Not Before" "verifyResults/$filename.txt"
    grep "Not After" "verifyResults/$filename.txt"

    #Format Clé publique
    echo "-------------------------------------------------------"
    echo "Vérifier les informations de la clé publique du porteur"
    echo "-------------------------------------------------------"
    grep "Public Key Algorithm" "verifyResults/$filename.txt"
    grep "Public-Key" "verifyResults/$filename.txt"
    grep "Exponent" "verifyResults/$filename.txt"

    #NOT Unique Identifiers
    echo "-------------------------------------------------"
    echo "Vérifier que Unique Identifiers n'est pas présent"
    echo "-------------------------------------------------"
    grep "Unique" "verifyResults/$filename.txt"

    #Vérifier la présence des X509v3 extensions:
    echo "------------------------------------------"
    echo "Vérifier la présence des X509v3 extensions"
    echo "------------------------------------------"
    grep "X509v3 extensions" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "-------------------------------------------------------------------------------------------------"
    echo "Key Usage: Critical"
    echo "AC: cRLSign, keyCertSign"
    echo "[RGS 2.0] Si l’AC signe des réponses OCSP, le bit digitalSignature doit être à 1."
    echo "Authentification: digitalSignature"
    echo "Signature: nonRepudiation"
    echo "[RGS 2.0] Confidentialité: Le bit keyEncipherment pour une clé RSA ou (exclusif) le bit keyAgreement ou (exclusif) le bit dataEncipherment doit être à 1, les autres bits à 0"
    echo "[RGS 2.0] Les bits nonRepudiation et digitalSignature doivent être à 1, les autres bits à 0."
    echo "[RGS 2.0] Authentification serveur (serveur): (si RSA) keyEncipherement, (si DH éphémère signé) digitalSignature, (si DH avec clé publique fixe) keyAgreement"
    echo "Authentification serveur (client): digitalSignature ou (exclusif) keyAgreement"
    echo "Cachet: digitalSignature (et éventuellement nonRepudiation)"
    echo "[RGS 2.0] Signature de code: digitalSignature"
    echo "-------------------------------------------------------------------------------------------------"
    grep -A 1 "X509v3 Key Usage" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "-------------------------------------------------------------------------------------------------------------------"
    echo "Extended Key Usage: non critique"
    echo "Signature Timestamping: id-kp-timeStamping"
    echo "[RGS 2.0] Signature responder OCSP: id-kp-OCSPSigning"
    echo "[RGS 2.0] Signature de code: id-kp-codeSigning"
    echo "[RGS 2.0] Authentification serveur (serveur): id-kp-serverAuth"
    echo "[RGS 2.0] Authentification serveur (client): id-kp-clientAuth"
    echo "-------------------------------------------------------------------------------------------------------------------"
    grep -A 1 "X509v3 Extended Key Usage" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "-----------------------------------------------"
    echo "Basic Constraints (Critical si certificat d'AC)"
    echo "[RGS 2.0] Pour les certificats d'AC utilisés pour la signature de certificats de personnes physiques ou de services applicatifs, le champ pathLenConstraint doit être positionné à 0"
    echo "[RGS 2.0] Pour les certificats d'AC utilisés pour la signature de certificats d’AC, il est recommandé de positionner dans le champ pathLenConstraint la valeur adéquate."
    echo "-----------------------------------------------"
    grep -A 1 "X509v3 Basic Constraints" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "--------------------------------------"
    echo "Authority Key Identifier: not critical"
    echo "[RGS 2.0] Pour tous les certificats porteurs, cette extension doit être présente, être marquée non critique et contenir l'identifiant de la clé publique de l'AC émettrice (même valeur que le champ Subject Key Identifier du certificat de cette AC émettrice)."
    echo "--------------------------------------"
    grep -A 1 "X509v3 Authority Key Identifier" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "--------------------"
    echo "Certificate Policies"
    echo "--------------------"
    grep -A 2 "X509v3 Certificate Policies" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "--------------------------------------------------"
    echo "Issuer Alternative Name (optionnel): not critical"
    echo "--------------------------------------------------"
    grep -A 1 "X509v3 Issuer Alternative Name" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "--------------------------------------------------"
    echo "Subject Alternative Name (optionnel): not critical"
    echo "[RGS 2.0] Pour les certificats serveurs de type SSL/TLS, le champ Subject Alternative Name doit être présent. Il doit contenir au moins une entrée de type DNS Name correspondant à l’un des FQDN du service applicatif hébergé par la machine"
    echo "--------------------------------------------------"
    grep -A 1 "X509v3 Subject Alternative Name" "verifyResults/$filename.txt" | sed -e "s/x509 /%/g"

    echo "-----------------------"
    echo "CRL Distribution Points"
    echo "-----------------------"
    grep -A 4 "X509v3 CRL Distribution Points" "verifyResults/$filename.txt"

    echo "----------------------"
    echo "[RGS 2.0] Freshest CRL"
    echo "[RGS 2.0] Si l'AC utilise des deltaLCR (ce qui est recommandé par les PC Types), cette extension doit être présente. Inversement, si ce champ est présent, l'AC doit fournir le service correspondant."
    echo "----------------------"
    grep -A 4 "Freshest" "verifyResults/$filename.txt"

    echo "-------------------------------"
    echo "CRL Distribution Points en ldap"
    echo "-------------------------------"
    grep "ldap" "verifyResults/$filename.txt"

    echo "----------------------------"
    echo "Authority Information Access"
    echo "----------------------------"
    grep -A 1 "Authority Information Access" "verifyResults/$filename.txt"

    echo "----------------------------"
    echo "Responder OCSP"
    echo "----------------------------"
    grep "OCSP" "verifyResults/$filename.txt"

    echo "------------"
    echo "QCStatements"
    echo "------------"
    grep -A 2 "qcStatements" "verifyResults/$filename.txt"
done

# Vérification des CRL 
for j in crl/*.crl
do
    echo "****************************************************************************************************************************"
    echo $j
    echo "****************************************************************************************************************************"
    openssl crl -text -noout -inform DER -in "$j" > "$j.txt"
    openssl asn1parse -inform DER -in "$j" > "$j.asn1.txt"
    issuerCN=$(grep -A 1 "commonName" "$j.asn1.txt" | sed -n '2,2p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')
    serial=$(grep -A 1 "CRL Number" "$j.asn1.txt" | sed -n '2,2p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')
    #filename=$(echo "$issuerCN")
    filename=$(echo "$issuerCN - CRL - $serial")
    mv "$j.txt" "verifyResults/$filename.crl.txt"
    mv "$j.asn1.txt" "verifyResults/$filename.crl.asn1.txt"
    #Version
    echo "-----------------------------------------------------------------------------------------"
    echo "Version: la valeur de ce champ doit être '1', indiquant qu'il s'agit d'une LCR version 2."
    echo "-----------------------------------------------------------------------------------------"
    grep "Version" "verifyResults/$filename.crl.txt"

    #CRL Number
    echo "------------------------"
    echo "CRL Number: non critique"
    echo "------------------------"
    grep -A 1 "CRL Number" "verifyResults/$filename.crl.txt"

    #Delta CRL Indicator
    echo "-------------------------------"
    echo "Delta CRL Indicator"
    echo "[RGS 2.0] si deltaCRL: critical"
    echo "-------------------------------"
    grep "Indicator" "verifyResults/$filename.crl.txt"

    #Signature
    echo "----------------------------------------------"
    echo "Signature: Vérifier l'algorithme de signature."
    echo "----------------------------------------------"
    grep "Signature Algorithm" "verifyResults/$filename.crl.txt" | sed -n '2,2p'

    #Issuer
    echo "------"
    echo "Issuer"
    echo "------"
    grep "Issuer:" "verifyResults/$filename.crl.txt"

    #Authority Key Identifier
    echo "--------------------------------------"
    echo "Authority Key Identifier: non critique"
    echo "--------------------------------------"
    grep -A 1 "Authority Key Identifier" "verifyResults/$filename.crl.txt"

    echo "-----------------------------------------------------------"
    echo "[RGS 2.0] Issuer Alternative Name (optionnel): not critical"
    echo "-----------------------------------------------------------"
    grep -A 1 "X509v3 Issuer Alternative Name" "verifyResults/$filename.crl.txt" | sed -e "s/x509 /%/g"

    #Update
    echo "----------------------------------------------------------------------------------------------------------------------------"
    echo "This Update"
    echo "[RGS 2.0] Next Update: (*) next update = this update + 72h*2"
    echo "[RGS 2.0] Next Update: (**) next update = this update + 24h*2"
    echo "[RGS 2.0] Next Update: (***) next update = this update + 36h"
    echo "----------------------------------------------------------------------------------------------------------------------------"
    grep "Update" "verifyResults/$filename.crl.txt"

    #Freshest CRL
    echo "----------------------"
    echo "[RGS 2.0] Freshest CRL"
    echo "[RGS 2.0] Si l'AC utilise des deltaLCR (ce qui est recommandé par les PC Types), cette extension doit être présente dans les LCR complètes (et absente dans les deltaLCR)"
    echo "----------------------"
    grep -A 4 "Freshest" "verifyResults/$filename.crl.txt"

    #Revoked Certificates: userCertificate, revocationDate, crlEntryExtensions
    echo "-------------------------------------------------------------------------"
    echo "Revoked Certificates: userCertificate, revocationDate, crlEntryExtensions"
    echo "Les raisons de révocation ne doivent pas être publiées"
    echo "[RGS 2.0] Pour les LCR qui comportent des numéros de série correspondant à des certificats d’unité d’horodatage, il est obligatoire de supporter l’extension d’entrée LCR : reasonCode"
    echo "-------------------------------------------------------------------------"
    grep -A 2 "CRL entry extensions:" "verifyResults/$filename.crl.txt"
done
