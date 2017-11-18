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

## Known issues

EcdsaSigner.java uses BouncyCastle crypto library for ECDSA. <br/>
In line 42, it uses a PKCS8EncodedKeySpec wrap a PemObject instance. <br/>
As for now, the conversion to PKCS#8 is needed as I have not figured out another way to inflate ECC private key yet. <br/>

In our school project, we assume that the companies can create their own signer (and not bound to any programming languages) as ECDSA is an open and well-defined. The only thing we have to agree on is which secure hash to use and we are using SHA384.

> Link to line 42 of EcdsaSigner.java <br/> https://github.com/yong24s/CS3235-AY1718S1-RetrofitSecureNFC/blob/afef89f0ce0225a0b5aa44b9ca8824889314c3f3/KeyGenerator/src/main/java/ECC/EcdsaSigner.java#L42 <br/>
> Link to StackOverflow solution: https://stackoverflow.com/questions/22963581/reading-elliptic-curve-private-key-from-file-with-bouncycastle#comment71074675_23369629
