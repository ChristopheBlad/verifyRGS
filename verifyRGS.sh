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

echo "----------"
echo "Certificat"
echo "----------"
grep "Subject:" $1.txt | sed -e "s/CN=/%/g" | cut -d'%' -f2 #coupe ce qui est apres
grep -A 1 "commonName" $1.asn1.txt | while read line
do
    echo "$line"
done
grep -A 1 "X509v3 Subject Key Identifier" $1.txt

#Vérifier la version
echo "-----------------------------------------"
echo "Vérifier la version x509: version 3 (0x2)"
echo "-----------------------------------------"
grep "Version" $1.txt

#Vérifier Issuer
echo "-----------------------------------------------"
echo "Vérifier que l'émetteur est bien l'AC qualifiée"
echo "-----------------------------------------------"
grep "Issuer:" $1.txt | sed -e "s/Issuer: /%/g" | cut -d'%' -f2 #coupe ce qui est apres

#Vérifier algorithme de signature
echo "----------------------------------"
echo "Vérifier l'algorithme de signature"
echo "----------------------------------"
grep "Signature Algorithm" $1.txt

#Validity
echo "--------------------------------------------------------"
echo "Vérifier la durée de vie (AC 10 ans, porteur 3 ans max.)"
echo "--------------------------------------------------------"
grep "Not Before" $1.txt
grep "Not After" $1.txt


#Subject dont encodage UTF8
echo "-------------------------------------------------------------------------------------------------"
echo "Référencement SGMAP - Vérifier l'encodage des champs (tout UTF8 sauf countryName PRINTABLESTRING)"
echo "-------------------------------------------------------------------------------------------------"
grep -A 1 "countryName" $1.asn1.txt
grep -A 1 "commonName" $1.asn1.txt


#Format Clé publique
echo "-------------------------------------------------------"
echo "Vérifier les informations de la clé publique du porteur"
echo "-------------------------------------------------------"
grep "Public Key Algorithm" $1.txt
grep "Public-Key" $1.txt
grep "Exponent" $1.txt

#NOT Unique Identifiers
echo "-------------------------------------------------"
echo "Vérifier que Unique Identifiers n'est pas présent"
echo "-------------------------------------------------"
grep "Unique" $1.txt

#Vérifier la présence des X509v3 extensions:
echo "------------------------------------------"
echo "Vérifier la présence des X509v3 extensions"
echo "------------------------------------------"
grep "X509v3 extensions" $1.txt | sed -e "s/x509 /%/g"

echo "-------------------"
echo "Key Usage: Critical"
echo "AC: cRLSign, keyCertSign"
echo "Authentification: digitalSignature"
echo "Signature, Cachet: nonRepudiation"
echo "Confidentialité: dataEncipherment"
echo "Authentification serveur: keyEncipherement"
echo "-------------------"
grep -A 1 "X509v3 Key Usage" $1.txt | sed -e "s/x509 /%/g"

echo "-----------------------------------------------"
echo "Basic Constraints (Critical si certificat d'AC)"
echo "-----------------------------------------------"
grep -A 1 "X509v3 Basic Constraints" $1.txt | sed -e "s/x509 /%/g"

echo "------------------------"
echo "Authority Key Identifier"
echo "------------------------"
grep -A 1 "X509v3 Authority Key Identifier" $1.txt | sed -e "s/x509 /%/g"

echo "--------------------"
echo "Certificate Policies"
echo "--------------------"
grep -A 2 "X509v3 Certificate Policies" $1.txt | sed -e "s/x509 /%/g"

echo "--------------------------------------------------"
echo "Subject Alternative Name (optionnel): not critical"
echo "--------------------------------------------------"
grep -A 1 "X509v3 Subject Alternative Name" $1.txt | sed -e "s/x509 /%/g"

echo "--------------------------------------------------"
echo "Issuer Alternative Name (optionnel): not critical"
echo "--------------------------------------------------"
grep -A 1 "X509v3 Issuer Alternative Name" $1.txt | sed -e "s/x509 /%/g"

echo "-----------------------"
echo "CRL Distribution Points"
echo "-----------------------"
grep -A 4 "X509v3 CRL Distribution Points" $1.txt

echo "--------------------------------------"
echo "Authority Information Access (si OCSP)"
echo "--------------------------------------"
grep -A 1 "Authority Information Access" $1.txt

echo "------------"
echo "QCStatements"
echo "------------"
grep -A 1 "QCStatements" $1.txt

echo "*************************************************************"
