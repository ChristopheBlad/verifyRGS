#!/bin/sh
#deux script, vérifier les certificats et vérifier les CRL

#Renommer les fichiers: issuerCN - subjectCN


#essayer de trouver une chaine "Certificate:", si oui enregistrer, si non changer encodage
openssl x509 -text -noout -in $1 -inform PEM > $1.txt

if grep "Certificate" $1.txt
then
	openssl x509 -text -noout -in $1 -inform PEM > $1.txt
    openssl asn1parse -in $1 -inform PEM > $1.asn1.txt
else
	openssl x509 -text -noout -in $1 -inform DER > $1.txt
    openssl asn1parse -in $1 -inform DER > $1.asn1.txt
fi

#Extraction du CN du porteur
issuerCN=$(grep -A 1 "commonName" $1.asn1.txt | sed -n '2,2p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')
subjectCN=$(grep -A 1 "commonName" $1.asn1.txt | sed -n '5,5p' | sed 's/\(.*\):\(.*\):\(.*\):\(.*\)/\4/')

filename=$(echo "$issuerCN - $subjectCN")
mv $1.txt "$filename.txt"
mv $1.asn1.txt "$filename.asn1.txt"

#Subject
echo "---------------------------------------------------------------------------------------------------"
echo "Identification du sujet"
echo "L'attribut countryName doit être présent. Il doit être renseigné en lettres majuscules."
echo "L'attribut organizationName doit être présent et doit contenir le nom officiel complet de l'entité."
echo "Une instance de l'attribut organizationalUnitName doit être présente: <00002> <SIRET/SIREN>."
echo "L'attribut commonName doit comporter le premier prénom suivi d'un espace, suivi du nom du porteur."
echo "il n'y a pas d'obligation à mentionner ces autres prénoms dans le certificat, mais s'ils le sont,"
echo "ils doivent l'être dans le même ordre que sur la pièce d'identité et séparés par une virgule"
echo "sans espace ni avant ni après la virgule."
echo "Référencement SGMAP - Vérifier l'encodage des champs (tout UTF8 sauf countryName PRINTABLESTRING)"
echo "---------------------------------------------------------------------------------------------------"
grep -A 1 "countryName" "$filename.asn1.txt" | sed -n '4,5p'
grep -A 1 "organizationName" "$filename.asn1.txt" | sed -n '4,5p'
grep -A 1 "organizationalUnitName" "$filename.asn1.txt" | sed -n '4,5p'
grep -A 1 "commonName" "$filename.asn1.txt" | sed -n '4,5p'

#Vérifier la version
echo "-----------------------------------------"
echo "Vérifier la version x509: version 3 (0x2)"
echo "-----------------------------------------"
grep "Version" "$filename.txt"

#Vérifier Issuer
echo "-----------------------------------------------"
echo "Vérifier que l'émetteur est bien l'AC qualifiée"
echo "-----------------------------------------------"
#grep "Issuer:" "$filename.txt" | sed -e "s/Issuer: /%/g" | cut -d'%' -f2 #coupe ce qui est apres
grep "Issuer:" "$filename.txt"

#Vérifier algorithme de signature
echo "----------------------------------"
echo "Vérifier l'algorithme de signature"
echo "----------------------------------"
grep "Signature Algorithm" "$filename.txt"

#Validity
echo "--------------------------------------------------------"
echo "Vérifier la durée de vie (AC 10 ans, porteur 3 ans max.)"
echo "--------------------------------------------------------"
grep "Not Before" "$filename.txt"
grep "Not After" "$filename.txt"

#Format Clé publique
echo "-------------------------------------------------------"
echo "Vérifier les informations de la clé publique du porteur"
echo "-------------------------------------------------------"
grep "Public Key Algorithm" "$filename.txt"
grep "Public-Key" "$filename.txt"
grep "Exponent" "$filename.txt"

#NOT Unique Identifiers
echo "-------------------------------------------------"
echo "Vérifier que Unique Identifiers n'est pas présent"
echo "-------------------------------------------------"
grep "Unique" "$filename.txt"

#Vérifier la présence des X509v3 extensions:
echo "------------------------------------------"
echo "Vérifier la présence des X509v3 extensions"
echo "------------------------------------------"
grep "X509v3 extensions" "$filename.txt" | sed -e "s/x509 /%/g"

echo "-------------------"
echo "Key Usage: Critical"
echo "AC: cRLSign, keyCertSign"
echo "Authentification: digitalSignature"
echo "Signature, Cachet: nonRepudiation"
echo "Confidentialité: dataEncipherment"
echo "Authentification serveur: keyEncipherement"
echo "-------------------"
grep -A 1 "X509v3 Key Usage" "$filename.txt" | sed -e "s/x509 /%/g"

echo "-----------------------------------------------"
echo "Basic Constraints (Critical si certificat d'AC)"
echo "-----------------------------------------------"
grep -A 1 "X509v3 Basic Constraints" "$filename.txt" | sed -e "s/x509 /%/g"

echo "------------------------"
echo "Authority Key Identifier"
echo "------------------------"
grep -A 1 "X509v3 Authority Key Identifier" "$filename.txt" | sed -e "s/x509 /%/g"

echo "--------------------"
echo "Certificate Policies"
echo "--------------------"
grep -A 2 "X509v3 Certificate Policies" "$filename.txt" | sed -e "s/x509 /%/g"

echo "--------------------------------------------------"
echo "Subject Alternative Name (optionnel): not critical"
echo "--------------------------------------------------"
grep -A 1 "X509v3 Subject Alternative Name" "$filename.txt" | sed -e "s/x509 /%/g"

echo "--------------------------------------------------"
echo "Issuer Alternative Name (optionnel): not critical"
echo "--------------------------------------------------"
grep -A 1 "X509v3 Issuer Alternative Name" "$filename.txt" | sed -e "s/x509 /%/g"

echo "-----------------------"
echo "CRL Distribution Points"
echo "-----------------------"
grep -A 4 "X509v3 CRL Distribution Points" "$filename.txt"

echo "--------------------------------------"
echo "Authority Information Access (si OCSP)"
echo "--------------------------------------"
grep -A 1 "Authority Information Access" "$filename.txt"

echo "------------"
echo "QCStatements"
echo "------------"
grep -A 1 "QCStatements" "$filename.txt"

echo "*************************************************************"
