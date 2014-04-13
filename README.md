verifyRGS
==============
Un script (utilisant openssl) permettant de vérifier si un certificat ou une CRL est conforme aux exigences du RGS.

Exigences extraites de l'annexe A14 du RGS v1.0: Profils de Certificats / LCR / OCSP et Algorithmes Cryptographiques, Version 2.3 du 11 février 2010

Prérequis: 
- openssl doit être installé sur le poste
- les certificats à vérifier doivent être nommés *.cer et être copiés dans le répertoire certificats/
- les crl à vérifier doivent être nommés *.crl et être copiés dans le répertoire crl/
