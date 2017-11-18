# RetrofitSecureNFC

Retrofitting cheap and low storage NTAG203/213 with Elliptic Curve Digital Signature Algorithm (ECDSA)!

## How to use

1. Generate an ECC private key and a self-signed ECC public certificate <br/>
> *Read: How to generate ECC keys/certificates*
2. Run **EcdsaSigner.java** in KeyGenerator Project to sign an URL with your ECC private key <br/>
3. [OPTIONAL] Run **EcdsaVerifier.java** in KeyGenerator Project to verify the signed URL with your ECC public certificate <br/>

## How to generate ECC keys/certificates

First, pick a named curve that fits your security requirements and NFC storage space. <br/>
> openssl ecparam -list_curves <br/>
> The following command assumes that **prime256v1** is chosen. <br/>

openssl ecparam -genkey -name **prime256v1** -noout -out tmp.pem  <br/>
> Discard this later as we need a PKCS#8 padded private key *Read: Known Issues*<br/>

openssl pkcs8 -topk8 -nocrypt -in tmp.pem -out key.pem  <br/>
> Keep this as the ECC private key <br/>

openssl req -new -sha256 -key key.pem -out csr.csr <br/>
> Create a certificate signing request (CSR) <br/>

openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem  <br/>
> Keep this as the ECC public certifcate <br/>

The following commands can be used to print the content of key and certifcate.
openssl x509 -in certificate.pem -text -noout  <br/>
openssl x509 -in key.pem -text -noout  <br/>
