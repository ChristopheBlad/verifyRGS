#!/bin/sh
#syntaxe verify "AC" "**" "signature" ou verify "porteur" "*" "authentification"
#deux script, vérifier les certificats et vérifier les CRL
#Faire peut-être un menu

#Renommer les fichiers: issuerCN - subjectCN

openssl x509 -text -noout -in $1 -inform PEM
#essayer de trouver une chaine "Certificate:", si oui enregistrer, si non changer encodage

echo "Le certificat s'affiche t'il correctement? (y/n)"

read encodage

if [ "$encodage" = "y" ]
then
	openssl x509 -text -noout -in $1 -inform PEM > $1.txt
    openssl asn1parse -in $1 -inform PEM > $1.asn1.txt
else
	openssl x509 -text -noout -in $1 -inform DER > $1.txt
    openssl asn1parse -in $1 -inform DER > $1.asn1.txt
fi

#Vérifier la version
if (grep "Version: 3" $1.txt)
then
    echo "Version OK (3)"
else
	echo "Version NOK (not 3)"
fi

#Vérifier Issuer
# grep "Issuer:" $1.txt | sed -e "s/ //g"
grep "Issuer:" $1.txt | sed -e "s/Issuer: /%/g" | cut -d'%' -f2 #coupe ce qui est apres


#Vérifier algorithm de signature
if (grep "Signature Algorithm: sha256WithRSAEncryption" $1.txt)
then
	echo "Signature Algorithm OK"
else
	if (grep "Signature Algorithm: sha1WithRSAEncryption" $1.txt)
    then echo "WARNING: SHA1"
    else echo "Signature Algorithm NOK"
    fi
fi

exit 0


grep "Signature Algorithm: sha256WithRSAEncryption"

grep "Issuer:"

#Validity

#Subject dont encodage UTF8

#Subject Public Key Info
#Public Key Algorithm: rsaEncryption
#Public-Key: (2048 bit)
#Exponent: 65537 (0x10001)

#NOT Unique Identifiers

#Vérifier la présence des X509v3 extensions:

grep "X509v3 Authority Key Identifier:"

                keyid:5F:A8:71:60:BF:55:89:58:B5:E3:ED:20:99:E1:67:37:48:A9:B1:E1


grep "X509v3 Key Usage: critical"

Digital Signature

            X509v3 Private Key Usage Period: 

                Not Before: Oct  8 13:50:13 2013 GMT, Not After: Oct  8 13:50:13 2014 GMT

grep "X509v3 Certificate Policies:"

                Policy: 1.3.6.1.4.1.22234.2.8.3.5

                  CPS: http://www.keynectis.com/PC/

#les champs Subject Alternative Name et Issuer Alternative Name peuvent être présents, mais ils doivent obligatoirement être marqués "non critique" et être conformes aux exigences du chapitre 3.2.1 du [RFC3739].

grep "X509v3 Basic Constraints: critical"

                CA:FALSE

            X509v3 Extended Key Usage: critical

                Time Stamping



grep "X509v3 CRL Distribution Points:"



                Full Name:

                  URI:http://trustcenter-crl.certificat2.com/Keynectis/Keynectis_CDS_CA_for_timestamping.crl



                Full Name:

                  URI:ldap://ldap.keynectis.com/CN=Keynectis%20CDS%20CA%20for%20timestamping,OU=KEYNECTIS%20CDS,OU=0002%20478217318,O=KEYNECTIS,C=FR?certificateRevocationList;binary?base?objectclass=pkiCA

grep "Authority Information Access"

QCStatements