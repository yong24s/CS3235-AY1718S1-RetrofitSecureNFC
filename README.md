# RetrofitSecureNFC

Retrofitting NTAG203/213 with ElGamal Signature Scheme!

## Generating certs

openssl ecparam -genkey -name prime256v1 -noout -out tmp.pem 
> discard this as we need PKCS#8 padded cert
openssl pkcs8 -topk8 -nocrypt -in tmp.pem -out key.pem 
> keep this as private key

openssl ec -in key.pem -pubout -out pub.pem 
> Not used

openssl req -new -sha256 -key key.pem -out csr.csr
> discard after use
openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem 
> keep this as public key

openssl x509 -in certificate.pem -text -noout 
openssl x509 -in key.pem -text -noout 
> for printing

## ccmobilelife.sg
> save file as domain name e.g. ccmobilelife.sg in android assets

-----BEGIN CERTIFICATE-----
MIICWjCCAgGgAwIBAgIJAMsd11jSMscIMAoGCCqGSM49BAMCMIGJMQswCQYDVQQG
EwJTRzESMBAGA1UECAwJU2luZ2Fwb3JlMRIwEAYDVQQHDAlTaW5nYXBvcmUxGDAW
BgNVBAoMD2NjbW9iaWxlbGlmZS5zZzEYMBYGA1UEAwwPY2Ntb2JpbGVsaWZlLnNn
MR4wHAYJKoZIhvcNAQkBFg9jY21vYmlsZWxpZmUuc2cwHhcNMTcxMTA1MjM0MzQ5
WhcNMTgxMTA1MjM0MzQ5WjCBiTELMAkGA1UEBhMCU0cxEjAQBgNVBAgMCVNpbmdh
cG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRgwFgYDVQQKDA9jY21vYmlsZWxpZmUu
c2cxGDAWBgNVBAMMD2NjbW9iaWxlbGlmZS5zZzEeMBwGCSqGSIb3DQEJARYPY2Nt
b2JpbGVsaWZlLnNnMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJFJx+Fkyjrf
kzMHXRHsh6R4EPD7lxqWj9qJd9iMJVng4vhHJh1+ehzXCfA65Gsr7qKnyOFum+gN
0yFLoUMuB6NQME4wHQYDVR0OBBYEFAclflYeL3EyDxwbEGNgy+7c3KZSMB8GA1Ud
IwQYMBaAFAclflYeL3EyDxwbEGNgy+7c3KZSMAwGA1UdEwQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgYuCguzcicmHRPSlNSIU1PEHZilrOZZzUpPqRVbQbwzoCIAdJ
kL+MJoTVT5zkLEZJy3fI2voORsqOHpqGKcBouk3P
-----END CERTIFICATE-----

-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvVDmildtbRaYT4S2
N9ZG9M8zDHUZNrtvUBA8X8HP0r6hRANCAASgkUnH4WTKOt+TMwddEeyHpHgQ8PuX
GpaP2ol32IwlWeDi+EcmHX56HNcJ8DrkayvuoqfI4W6b6A3TIUuhQy4H
-----END PRIVATE KEY-----
