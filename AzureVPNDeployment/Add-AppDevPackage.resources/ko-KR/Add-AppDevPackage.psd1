# Localized	02/22/2024 08:42 AM (GMT)	303:7.1.41104 	Add-AppDevPackage.psd1
# Culture = "en-US"
ConvertFrom-StringData @'
###PSLOC
PromptYesString=예(&Y)
PromptNoString=아니요(&N)
BundleFound=찾은 번들: {0}
PackageFound=찾은 패키지: {0}
EncryptedBundleFound=암호화된 번들 찾음: {0}
EncryptedPackageFound=암호화된 패키지 찾음: {0}
CertificateFound=찾은 인증서: {0}
DependenciesFound=찾은 종속성 패키지:
GettingDeveloperLicense=개발자 라이선스를 취득하는 중...
InstallingCertificate=인증서를 설치하는 중...
InstallingPackage=\n앱을 설치하는 중...
AcquireLicenseSuccessful=개발자 라이선스를 취득했습니다.
InstallCertificateSuccessful=인증서가 설치되었습니다.
Success=\n성공: 앱이 설치되었습니다.
WarningInstallCert=\n컴퓨터의 신뢰된 사용자 인증서 저장소에 디지털 인증서를 설치하려고 합니다. 이렇게 하면 보안상 심각하게 위험해지므로 이 디지털 인증서를 만든 사람을 신뢰하는 경우에만 해당 인증서를 설치해야 합니다.\n\n이 앱을 다 사용한 후에는 연결된 디지털 인증서를 수동으로 제거해야 합니다. 이 작업을 수행하는 방법에 대한 지침은 다음에서 확인할 수 있습니다. http://go.microsoft.com/fwlink/?LinkId=243053\n\n계속하시겠습니까?\n\n
ElevateActions=\n이 앱을 설치하기 전에 다음을 수행해야 합니다.
ElevateActionDevLicense=\t- 개발자 라이선스 취득
ElevateActionCertificate=\t- 서명 인증서 설치
ElevateActionsContinue=계속하려면 관리자 자격 증명이 필요합니다. UAC 프롬프트를 확인하고 메시지가 표시되는 경우 관리자 암호를 제공하십시오.
ErrorForceElevate=계속하려면 관리자 자격 증명을 제공해야 합니다.  이 스크립트를 -Force 매개 변수 없이 실행하거나 권한이 높은 PowerShell 창에서 실행하십시오.
ErrorForceDeveloperLicense=개발자 라이선스를 취득하려면 사용자 상호 작용이 필요합니다.  스크립트를 -Force 매개 변수 없이 다시 실행하십시오.
ErrorLaunchAdminFailed=오류: 관리자로 새 프로세스를 시작할 수 없습니다.
ErrorNoScriptPath=오류: 이 스크립트를 파일에서 시작해야 합니다.
ErrorNoPackageFound=오류: 스크립트 디렉터리에서 패키지 또는 번들을 찾을 수 없습니다.  설치하려는 패키지 또는 번들이 이 스크립트와 같은 디렉터리에 있는지 확인하십시오.
ErrorManyPackagesFound=오류: 스크립트 디렉터리에 둘 이상의 패키지 또는 번들이 있습니다.  설치하려는 패키지 또는 번들만 이 스크립트와 같은 디렉터리에 있는지 확인하십시오.
ErrorPackageUnsigned=오류: 패키지 또는 번들이 디지털 서명되지 않았거나 해당 서명이 손상되었습니다.
ErrorNoCertificateFound=오류: 스크립트 디렉터리에서 인증서를 찾을 수 없습니다.  설치하려는 패키지 또는 번들을 서명하는 데 사용된 인증서가 이 스크립트와 같은 디렉터리에 있는지 확인하십시오.
ErrorManyCertificatesFound=오류: 스크립트 디렉터리에 둘 이상의 인증서가 있습니다.  설치하려는 패키지 또는 번들을 서명하는 데 사용된 인증서만 이 스크립트와 같은 디렉터리에 있는지 확인하세요.
ErrorBadCertificate=오류: "{0}" 파일이 올바른 디지털 인증서가 아닙니다. CertUtil에서 오류 코드 {1}이(가) 반환되었습니다.
ErrorExpiredCertificate=오류: 개발자 인증서 "{0}"이(가) 만료되었습니다. 시스템 클록이 올바른 날짜 및 시간으로 설정되지 않은 것 같습니다. 시스템 설정이 올바른 경우 앱 소유자에게 유효한 인증서로 패키지 또는 번들을 다시 만들도록 요청하십시오.
ErrorCertificateMismatch=오류: 인증서가 패키지 또는 번들을 서명하는 데 사용된 인증서와 일치하지 않습니다.
ErrorCertIsCA=오류: 인증서는 인증 기관일 수 없습니다.
ErrorBannedKeyUsage=오류: 인증서의 키 사용은 {0}일 수 없습니다. 키 사용을 지정하지 않거나 키 사용이 "DigitalSignature"와 같아야 합니다.
ErrorBannedEKU=오류: 인증서의 확장 키 사용은 {0}일 수 없습니다. 코드 서명 및 영구 서명 EKU만 사용할 수 있습니다.
ErrorNoBasicConstraints=오류: 인증서에 기본 제약 조건 확장이 없습니다.
ErrorNoCodeSigningEku=오류: 인증서에 코드 서명용 확장 키 사용이 없습니다.
ErrorInstallCertificateCancelled=오류: 인증서 설치가 취소되었습니다.
ErrorCertUtilInstallFailed=오류: 인증서를 설치할 수 없습니다. CertUtil에서 오류 코드 {0}이(가) 반환되었습니다.
ErrorGetDeveloperLicenseFailed=오류: 개발자 라이선스를 취득할 수 없습니다. 자세한 내용은 http://go.microsoft.com/fwlink/?LinkID=252740을 참조하십시오.
ErrorInstallCertificateFailed=오류: 인증서를 설치할 수 없습니다. 상태: {0}. 자세한 내용은 http://go.microsoft.com/fwlink/?LinkID=252740을 참조하십시오.
ErrorAddPackageFailed=오류: 앱을 설치할 수 없습니다.
ErrorAddPackageFailedWithCert=오류: 앱을 설치할 수 없습니다.  보안을 위해 앱을 설치할 수 있을 때까지 서명 인증서를 제거해 보십시오.  이 작업을 수행하는 방법에 대한 지침은 다음에서 확인할 수 있습니다.\nhttp://go.microsoft.com/fwlink/?LinkId=243053
'@

# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAhVkxkU6hVdy7f
# jfppqp1yTKQGNfHzGjXkRxA2YQEYsaCCDYUwggYDMIID66ADAgECAhMzAAADri01
# UchTj1UdAAAAAAOuMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwODU5WhcNMjQxMTE0MTkwODU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQD0IPymNjfDEKg+YyE6SjDvJwKW1+pieqTjAY0CnOHZ1Nj5irGjNZPMlQ4HfxXG
# yAVCZcEWE4x2sZgam872R1s0+TAelOtbqFmoW4suJHAYoTHhkznNVKpscm5fZ899
# QnReZv5WtWwbD8HAFXbPPStW2JKCqPcZ54Y6wbuWV9bKtKPImqbkMcTejTgEAj82
# 6GQc6/Th66Koka8cUIvz59e/IP04DGrh9wkq2jIFvQ8EDegw1B4KyJTIs76+hmpV
# M5SwBZjRs3liOQrierkNVo11WuujB3kBf2CbPoP9MlOyyezqkMIbTRj4OHeKlamd
# WaSFhwHLJRIQpfc8sLwOSIBBAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhx/vdKmXhwc4WiWXbsf0I53h8T8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMTgzNjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AGrJYDUS7s8o0yNprGXRXuAnRcHKxSjFmW4wclcUTYsQZkhnbMwthWM6cAYb/h2W
# 5GNKtlmj/y/CThe3y/o0EH2h+jwfU/9eJ0fK1ZO/2WD0xi777qU+a7l8KjMPdwjY
# 0tk9bYEGEZfYPRHy1AGPQVuZlG4i5ymJDsMrcIcqV8pxzsw/yk/O4y/nlOjHz4oV
# APU0br5t9tgD8E08GSDi3I6H57Ftod9w26h0MlQiOr10Xqhr5iPLS7SlQwj8HW37
# ybqsmjQpKhmWul6xiXSNGGm36GarHy4Q1egYlxhlUnk3ZKSr3QtWIo1GGL03hT57
# xzjL25fKiZQX/q+II8nuG5M0Qmjvl6Egltr4hZ3e3FQRzRHfLoNPq3ELpxbWdH8t
# Nuj0j/x9Crnfwbki8n57mJKI5JVWRWTSLmbTcDDLkTZlJLg9V1BIJwXGY3i2kR9i
# 5HsADL8YlW0gMWVSlKB1eiSlK6LmFi0rVH16dde+j5T/EaQtFz6qngN7d1lvO7uk
# 6rtX+MLKG4LDRsQgBTi6sIYiKntMjoYFHMPvI/OMUip5ljtLitVbkFGfagSqmbxK
# 7rJMhC8wiTzHanBg1Rrbff1niBbnFbbV4UDmYumjs1FIpFCazk6AADXxoKCo5TsO
# zSHqr9gHgGYQC2hMyX9MGLIpowYCURx3L7kUiGbOiMwaMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAOuLTVRyFOPVR0AAAAA
# A64wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILkG
# XodDRBeOMikIBAEDIDPomEH0DlKaaL1YAPysrUPOMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAlKNmTUu1Vc8dTSGD8SzLct3ElnV2N+Fu9guc
# +60Q8BoI9C+o4lCP3sQZPhjs6JquqiQztoQjxV1IVGx6ci5QV0z4iL0f7FppIV/E
# Hp1M846RwuTIFIDj1jQHbxLlxZRRLxT8+oVgmiGc/+Sx3Rz/Vmvngku7Lq4/OqoQ
# SYhRUYkuo0Qs4qoNm2Da6ei35QiL9Ppoi22VN5HZ/AcWrX/1ur1Aw76727xMdaYR
# DMzsAxF/LxOV9iuLBlqGa0Sw8xkUjejlu3xaIDdjTmu5eVu/9QJ1GQwHlHsD7ROF
# XIymaOR+RwtrnUV9NzYvS1ReAir70wmp5d7Ek9bWp4A7nIGgdKGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBpvvtvmShJCwZVHpHEkEys0Q7X3Ppu6hj1
# j5zEh33ROQIGZh/HOqS6GBMyMDI0MDQyNjEwMDcxMC4zNjRaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAHj372b
# mhxogyIAAQAAAeMwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjMxMDEyMTkwNzI5WhcNMjUwMTEwMTkwNzI5WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL6k
# DWgeRp+fxSBUD6N/yuEJpXggzBeNG5KB8M9AbIWeEokJgOghlMg8JmqkNsB4Wl1N
# EXR7cL6vlPCsWGLMhyqmscQu36/8h2bx6TU4M8dVZEd6V4U+l9gpte+VF91kOI35
# fOqJ6eQDMwSBQ5c9ElPFUijTA7zV7Y5PRYrS4FL9p494TidCpBEH5N6AO5u8wNA/
# jKO94Zkfjgu7sLF8SUdrc1GRNEk2F91L3pxR+32FsuQTZi8hqtrFpEORxbySgiQB
# P3cH7fPleN1NynhMRf6T7XC1L0PRyKy9MZ6TBWru2HeWivkxIue1nLQb/O/n0j2Q
# Vd42Zf0ArXB/Vq54gQ8JIvUH0cbvyWM8PomhFi6q2F7he43jhrxyvn1Xi1pwHOVs
# bH26YxDKTWxl20hfQLdzz4RVTo8cFRMdQCxlKkSnocPWqfV/4H5APSPXk0r8Cc/c
# Mmva3g4EvupF4ErbSO0UNnCRv7UDxlSGiwiGkmny53mqtAZ7NLePhFtwfxp6ATIo
# jl8JXjr3+bnQWUCDCd5Oap54fGeGYU8KxOohmz604BgT14e3sRWABpW+oXYSCyFQ
# 3SZQ3/LNTVby9ENsuEh2UIQKWU7lv7chrBrHCDw0jM+WwOjYUS7YxMAhaSyOahpb
# udALvRUXpQhELFoO6tOx/66hzqgjSTOEY3pu46BFAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUsa4NZr41FbehZ8Y+ep2m2YiYqQMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBALe+my6p1NPMEW1t70a8Y2hGxj6siDSulGAs4UxmkfzxMAic4j0+GTPbHxk1
# 93mQ0FRPa9dtbRbaezV0GLkEsUWTGF2tP6WsDdl5/lD4wUQ76ArFOencCpK5svE0
# sO0FyhrJHZxMLCOclvd6vAIPOkZAYihBH/RXcxzbiliOCr//3w7REnsLuOp/7vlX
# JAsGzmJesBP/0ERqxjKudPWuBGz/qdRlJtOl5nv9NZkyLig4D5hy9p2Ec1zaotiL
# iHnJ9mlsJEcUDhYj8PnYnJjjsCxv+yJzao2aUHiIQzMbFq+M08c8uBEf+s37YbZQ
# 7XAFxwe2EVJAUwpWjmtJ3b3zSWTMmFWunFr2aLk6vVeS0u1MyEfEv+0bDk+N3jms
# CwbLkM9FaDi7q2HtUn3z6k7AnETc28dAvLf/ioqUrVYTwBrbRH4XVFEvaIQ+i7es
# DQicWW1dCDA/J3xOoCECV68611jriajfdVg8o0Wp+FCg5CAUtslgOFuiYULgcxnq
# zkmP2i58ZEa0rm4LZymHBzsIMU0yMmuVmAkYxbdEDi5XqlZIupPpqmD6/fLjD4ub
# 0SEEttOpg0np0ra/MNCfv/tVhJtz5wgiEIKX+s4akawLfY+16xDB64Nm0HoGs/Gy
# 823ulIm4GyrUcpNZxnXvE6OZMjI/V1AgSAg8U/heMWuZTWVUMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAPYiXu8ORQ4hvKcuE
# 7GK0COgxWnqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOnVeS0wIhgPMjAyNDA0MjYwODUxNTdaGA8yMDI0MDQy
# NzA4NTE1N1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6dV5LQIBADAHAgEAAgIA
# szAHAgEAAgIS5zAKAgUA6dbKrQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AFfoWhgPncPQ+4rMUqV32CkHh0wIC3cZR7Kow4qCOFIUYiWjC5oahe5OUkDOCVYj
# imwa9tRaxNyOVBz8PFWBoLGZ7R0+0g9L+FvG1rLvMYbHgqv3kNEBNJl89mzNcUOI
# QP6N/3PDuBDmJPnHPL2WKOf1lxYNg3s19awv9MbWntghMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHj372bmhxogyIAAQAA
# AeMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgh5TMiiEhJ5Ba2XLYj4EGOxTlC0t/Qc0JJPfJZ98G
# slgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAz1COr5bD+ZPdEgQjWvcIW
# uDJcQbdgq8Ndj0xyMuYmKjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB49+9m5ocaIMiAAEAAAHjMCIEIAqKcWF9DdRjhGs5RiHWtZZ2
# GniAF3fkZBxOsM5wKzJ0MA0GCSqGSIb3DQEBCwUABIICAKMDMOvgmXvVrGtjDhVS
# MUSCeJR3EJEgOr2VGlSVpixkhkvjYo3GACJPyaVBCEf7rZiymDAdoxjJ+a/EbWDr
# p4SVoZLiVT2l6YOMQ2ICSIuNeHdQmssm1+HpAQLF2m/xKsRFDeqKeon5uCAwW/YE
# Dvz6znKIkyn5fl6ZNuKZVbdBFLR74eq9dDn5XY/pYbPfALLTBKpoAo+yK78zHNm0
# bPxw9wQE5RQUbGv1+6BiMVoQpW/QnoIJ3zjjakyKH9ZU5JlYE12KJCqNIS25tWMl
# n8OTDLOeVgF2bthocbuvkBnYdsMbbSUK2Bgibab1+qZ5cMW97BxSWwHHgJI1U1Pm
# tzWF5rvRuWEHWRU3XAS1PD+w+GADYeF8nIa04P0eSqeh2xfQkbW1uDEiLCWyb4Uv
# 9m+YpE9Yd3OUneCS42WeTwrFdP2hselDinDGW5Jso8SWDI8n7QHlinzBOoSYqfeR
# 3gRLfENDyflkpFrpd7a4HNUzivfrCkjS4AesbiG3I3S58BLttCeaeUaSGVBgr1+l
# MENyihuNC5C/pSOO2tkJUyfcclSzUk1Lbr7VGrsp9G+Rx9/6G5jeSjkDBOgY9AJj
# 6VMAlf3aQ4+m8bMsFEMKeHh3XDArTapjohA+o7zsO/NuQqm8+OuPa9X0+69Cfjxe
# MyYNvZjIvbsSkveMquA3b+Yt
# SIG # End signature block
