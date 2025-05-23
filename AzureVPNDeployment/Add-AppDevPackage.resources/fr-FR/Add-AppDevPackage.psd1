# Localized	02/22/2024 08:42 AM (GMT)	303:7.1.41104 	Add-AppDevPackage.psd1
# Culture = "en-US"
ConvertFrom-StringData @'
###PSLOC
PromptYesString=O&ui
PromptNoString=&Non
BundleFound=Lot trouvé : {0}
PackageFound=Package trouvé : {0}
EncryptedBundleFound=Lot chiffré trouvé : {0}
EncryptedPackageFound=Package chiffré trouvé : {0}
CertificateFound=Certificat trouvé : {0}
DependenciesFound=Package(s) de dépendance trouvé(s) :
GettingDeveloperLicense=Acquisition de la licence de développeur...
InstallingCertificate=Installation du certificat...
InstallingPackage=\nInstallation de l'application…
AcquireLicenseSuccessful=Une licence de développeur a été correctement acquise.
InstallCertificateSuccessful=Le certificat a été correctement installé.
Success=\nOpération réussie : votre application a été correctement installée.
WarningInstallCert=\nVous êtes sur le point d'installer un certificat numérique dans le magasin de certificats Personnes autorisées de votre ordinateur. Cette opération comporte un grave risque de sécurité et elle ne doit être exécutée que si l'émetteur de ce certificat numérique est fiable.\n\nLorsque vous avez fini d'utiliser cette application, vous devez supprimer manuellement le certificat numérique associé. Des instructions se rapportant à cette procédure sont disponibles à cette adresse : http://go.microsoft.com/fwlink/?LinkId=243053\n\nVoulez-vous vraiment continuer ?\n\n
ElevateActions=\nAvant d'installer cette application, vous devez exécuter les tâches suivantes :
ElevateActionDevLicense=\t- Acquérir une licence de développeur
ElevateActionCertificate=\t- Installer le certificat de signature
ElevateActionsContinue=Des informations d'identification d'administrateur sont nécessaires pour continuer. Acceptez l'invite du contrôle de compte d'utilisateur et entrez votre mot de passe d'administrateur si nécessaire.
ErrorForceElevate=Vous devez fournir des informations d'identification d'administrateur pour continuer. Exécutez ce script sans le paramètre -Force ou dans une fenêtre PowerShell avec des privilèges élevés.
ErrorForceDeveloperLicense=L'acquisition d'une licence de développeur requiert l'intervention de l'utilisateur. Réexécutez le script sans le paramètre -Force.
ErrorLaunchAdminFailed=Erreur : impossible de démarrer un nouveau processus en tant qu'administrateur.
ErrorNoScriptPath=Erreur : vous devez lancer ce script à partir d'un fichier.
ErrorNoPackageFound=Erreur : aucun package ou lot trouvé dans le répertoire de scripts. Vérifiez que le package ou lot que vous voulez installer se trouve dans le même répertoire que ce script.
ErrorManyPackagesFound=Erreur : plusieurs packages ou lots trouvés dans le répertoire de scripts. Vérifiez que seul le package ou lot que vous voulez installer se trouve dans le même répertoire que ce script.
ErrorPackageUnsigned=Erreur : le package ou lot n'est pas signé numériquement ou sa signature est endommagée.
ErrorNoCertificateFound=Erreur : aucun certificat trouvé dans le répertoire de scripts. Vérifiez que le certificat utilisé pour signer le package ou lot que vous installez se trouve dans le même répertoire que ce script.
ErrorManyCertificatesFound=Erreur : plusieurs certificats trouvés dans le répertoire de scripts. Vérifiez que seul le certificat utilisé pour signer le package ou le lot que vous installez se trouve dans le même répertoire que ce script.
ErrorBadCertificate=Erreur : le fichier "{0}" n'est pas un certificat numérique valide. CertUtil retourné avec le code d'erreur {1}.
ErrorExpiredCertificate=Erreur : le certificat de développeur "{0}" a expiré. Cela peut être dû à un mauvais réglage de la date et de l'heure de l'horloge système. Si les paramètres système sont corrects, contactez le propriétaire de l'application afin qu'il recrée le package ou le lot avec un certificat valide.
ErrorCertificateMismatch=Erreur : le certificat ne correspond pas à celui utilisé pour signer le package ou le lot.
ErrorCertIsCA=Erreur : le certificat ne peut pas être une autorité de certification.
ErrorBannedKeyUsage=Erreur : le certificat ne peut pas avoir l'utilisation de clé suivante : {0}. L'utilisation de la clé ne doit pas être spécifiée ou elle doit être égale à "DigitalSignature".
ErrorBannedEKU=Erreur : le certificat ne peut pas avoir l'utilisation améliorée de la clé suivante : {0}. Seules les utilisations améliorées de la clé (EKU) Signature du code et Signature permanente sont autorisées.
ErrorNoBasicConstraints=Erreur : le certificat ne contient pas les extensions de contraintes de base.
ErrorNoCodeSigningEku=Erreur : le certificat ne contient pas l'utilisation améliorée de la clé pour Signature du code.
ErrorInstallCertificateCancelled=Erreur : l'installation du certificat a été annulée.
ErrorCertUtilInstallFailed=Erreur : impossible d'installer le certificat. CertUtil retourné avec le code d'erreur {0}.
ErrorGetDeveloperLicenseFailed=Erreur : impossible d'acquérir une licence de développeur. Pour plus d'informations, consultez http://go.microsoft.com/fwlink/?LinkID=252740.
ErrorInstallCertificateFailed=Erreur : impossible d'installer le certificat. État : {0}. Pour plus d'informations, consultez http://go.microsoft.com/fwlink/?LinkID=252740.
ErrorAddPackageFailed=Erreur : impossible d'installer l'application.
ErrorAddPackageFailedWithCert=Erreur : impossible d'installer l'application. Pour garantir la sécurité, pensez à désinstaller le certificat de signature jusqu'à ce que vous puissiez installer l'application. Des instructions se rapportant à cette procédure sont disponibles à cette adresse : \nhttp://go.microsoft.com/fwlink/?LinkId=243053
'@

# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhNUHo4UDU0U0J
# QaNV152CP9hnNJA01DRvZOUT32WPO6CCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDEBoTvxZPz3/smMSo7WMoj1
# A8WDC9ihEefOWfp9A+EOMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAFDaqCpe0rXrkNp/bliHru4IymnZABV8x+cipPz82burZj4Kb6+9iuxNO
# gm88il6m6NonZu9+48zMN5ougCEesCK4wL6bIDKjgDRzeluyL8edPmlfYezV+ZtT
# oQGRFvWfFAr3fQaSh/nZHcUR2UfB4BEUQ6PQwVMgiHofFR7hEJCDCKLe2JsHBs1i
# AfgrVzH3F5ryre++UcILRZTArvo86hm25DDW20kcxfHm7BwggUQFzuCpx3QEshpz
# Kj3op/pX16Bw/hA11T8cWma7Ibv+t9iqw4bwdR85utk/thCs0pX6gHIoimwLDL1h
# TCuL/DL3HEzacqLgnSFyRyrEsAV0eKGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAMP+t0nrNdMu1Kj0nDqFtL+x0nVw3rl6f1qKaAJCto5gIGZh/S7acY
# GBMyMDI0MDQyNjEwMDcwOS41OTZaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAHlj2rA8z20C6MAAQAAAeUwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMx
# MDEyMTkwNzM1WhcNMjUwMTEwMTkwNzM1WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRC
# ODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKl74Drau2O6LLrJO3HyTvO9
# aXai//eNyP5MLWZrmUGNOJMPwMI08V9zBfRPNcucreIYSyJHjkMIUGmuh0rPV5/2
# +UCLGrN1P77n9fq/mdzXMN1FzqaPHdKElKneJQ8R6cP4dru2Gymmt1rrGcNe800C
# cD6d/Ndoommkd196VqOtjZFA1XWu+GsFBeWHiez/PllqcM/eWntkQMs0lK0zmCfH
# +Bu7i1h+FDRR8F7WzUr/7M3jhVdPpAfq2zYCA8ZVLNgEizY+vFmgx+zDuuU/GChD
# K7klDcCw+/gVoEuSOl5clQsydWQjJJX7Z2yV+1KC6G1JVqpP3dpKPAP/4udNqpR5
# HIeb8Ta1JfjRUzSv3qSje5y9RYT/AjWNYQ7gsezuDWM/8cZ11kco1JvUyOQ8x/JD
# kMFqSRwj1v+mc6LKKlj//dWCG/Hw9ppdlWJX6psDesQuQR7FV7eCqV/lfajoLpPN
# x/9zF1dv8yXBdzmWJPeCie2XaQnrAKDqlG3zXux9tNQmz2L96TdxnIO2OGmYxBAA
# ZAWoKbmtYI+Ciz4CYyO0Fm5Z3T40a5d7KJuftF6CToccc/Up/jpFfQitLfjd71cS
# +cLCeoQ+q0n0IALvV+acbENouSOrjv/QtY4FIjHlI5zdJzJnGskVJ5ozhji0YRsc
# v1WwJFAuyyCMQvLdmPddAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU3/+fh7tNczEi
# fEXlCQgFOXgMh6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBADP6whOFjD1ad8Gk
# EJ9oLBuvfjndMyGQ9R4HgBKSlPt3pa0XVLcimrJlDnKGgFBiWwI6XOgw82hdolDi
# MDBLLWRMTJHWVeUY1gU4XB8OOIxBc9/Q83zb1c0RWEupgC48I+b+2x2VNgGJUsQI
# yPR2PiXQhT5PyerMgag9OSodQjFwpNdGirna2rpV23EUwFeO5+3oSX4JeCNZvgyU
# OzKpyMvqVaubo+Glf/psfW5tIcMjZVt0elswfq0qJNQgoYipbaTvv7xmixUJGTbi
# xYifTwAivPcKNdeisZmtts7OHbAM795ZvKLSEqXiRUjDYZyeHyAysMEALbIhdXgH
# Eh60KoZyzlBXz3VxEirE7nhucNwM2tViOlwI7EkeU5hudctnXCG55JuMw/wb7c71
# RKimZA/KXlWpmBvkJkB0BZES8OCGDd+zY/T9BnTp8si36Tql84VfpYe9iHmy7Pqq
# xqMF2Cn4q2a0mEMnpBruDGE/gR9c8SVJ2ntkARy5SfluuJ/MB61yRvT1mUx3lypp
# O22ePjBjnwoEvVxbDjT1jhdMNdevOuDeJGzRLK9HNmTDC+TdZQlj+VMgIm8ZeEIR
# NF0oaviF+QZcUZLWzWbYq6yDok8EZKFiRR5otBoGLvaYFpxBZUE8mnLKuDlYobjr
# xh7lnwrxV/fMy0F9fSo2JxFmtLgtMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoz
# QkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUA942iGuYFrsE4wzWDd85EpM6RiwqggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOnVhTkwIhgPMjAyNDA0MjYwOTQzMjFaGA8yMDI0MDQyNzA5NDMyMVowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6dWFOQIBADAHAgEAAgIVqDAHAgEAAgIRPTAKAgUA
# 6dbWuQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEpgtnbDwpbP05xugpDE
# Nln4bK1M+9cv0W2gSHYt7vmso1fwquVLnOfHmhAOP8FmHCHShekos4ZZHQlgvqx7
# CwCNhBZ/6cxEidorD7plszir8Jdj3STk89h2LwrYnBJ0XLeQsXkqBOdTdUbIUUnf
# zA6qXxFaxQ1RSsmsJ8y1m8MxMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAHlj2rA8z20C6MAAQAAAeUwDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgqEwdICECR8JEHyEv/jr2Kz2pdiFM4qjprfkWpZo0GKcwgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCAVqdP//qjxGFhe2YboEXeb8I/pAof01CwhbxUH9U69
# 7TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB5Y9q
# wPM9tAujAAEAAAHlMCIEIAEHRCumpjX53A+u3w1fAYa1S9zK4oUspSu5o1+qkCNe
# MA0GCSqGSIb3DQEBCwUABIICAGCRHAJCzEyY9EtQ4UIc/eX7qYRFKFP8dZWJ+wxF
# 68yq7tWb25B95HnXduGHSc3x+ehJLWI65YMYByHTwQRT2EhYtNvPViF88napia79
# JZfReBcBvJlWfXUZgXS1OT3ajWeNOba3QwXzc7ThPo8UQPAz7SCwg050vs7Fq5bY
# kCxPEoHqJDEDJANhndTkh0u+VuoF4LqAv2RtWV2z3HtMTlBtrMiD22ns8IRdojVN
# FhC8WBobPWofVdsIi9LgBKny3zEycDhdVPgboHZ4WS9RpK2k9EOldVU42K4kdw1s
# BgD2y5Sx4LrbB3JkHyhp/CsxeoV8NVRsjO+u1NpvXW1RZIHOCahPVMDN+g8/lQCZ
# /6pqLRuLSPwvhlnUGCjrBOWxgU/orwqEl9uuRKzH7OC5sr6YcldVWUqNBlb5MJwe
# 8K6kshlzGXZG2rUIZffKc5ezu7aqsIMl2scGsR0limZtvfe1T6/txFKi6CbN6cGs
# 5zMNLOb/LAwtWRYQN1lgi4zw7gtpQln0epQIxToK7Vg2AV4p+Y1P6KK2/nK4SRPw
# ICVNsEjdHiugFa+2Ca1Fd1SIuTz+ehzNhDM9UnXPTTm+YfWxFlVZWxlR0f3uy7G3
# GnE9wCV+DWq5TtZtSxZfCVzu4cDqhhrvwrVeUk9/VX5eH2ukXhXngL6d/czkWBpg
# 0noP
# SIG # End signature block
