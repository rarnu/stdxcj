# x509 Package

## class X509Certificate

```cangjie
public class X509Certificate <: Equatable<X509Certificate> & Hashable & ToString {
    public init(
        certificateInfo: X509CertificateInfo,
        parent!: X509Certificate,
        publicKey!: PublicKey,
        privateKey!: PrivateKey,
        signatureAlgorithm!: ?SignatureAlgorithm = None
    )
}
```

Functionality: X509 digital certificate is a type of digital certificate used for encrypted communication, serving as one of the core components of Public Key Infrastructure (PKI). The X509 digital certificate contains an entity's public key and identity information, used to verify the entity's identity and ensure communication security.

Parent Types:

- Equatable\<[X509Certificate](#class-x509certificate)>
- Hashable
- ToString

### prop dnsNames

```cangjie
public prop dnsNames: Array<String>
```

Functionality: Parses domain names from the Subject Alternative Names of the digital certificate.

Type: Array\<String>

### prop emailAddresses

```cangjie
public prop emailAddresses: Array<String>
```

Functionality: Parses email addresses from the Subject Alternative Names of the digital certificate.

Type: Array\<String>

### prop extKeyUsage

```cangjie
public prop extKeyUsage: ExtKeyUsage
```

Functionality: Parses the extended key usage from the digital certificate.

Type: [ExtKeyUsage](x509_package_structs.md#struct-extkeyusage)

### prop issuer

```cangjie
public prop issuer: X509Name
```

Functionality: Parses the issuer information of the digital certificate.

Type: [X509Name](x509_package_classes.md#class-x509name)

### prop IPAddresses

```cangjie
public prop IPAddresses: Array<IP>
```

Functionality: Parses [IP](x509_package_type.md#type-ip) addresses from the Subject Alternative Names of the digital certificate.

Type: Array\<[IP](x509_package_type.md#type-ip)>

### prop keyUsage

```cangjie
public prop keyUsage: KeyUsage
```

Functionality: Parses the key usage from the digital certificate.

Type: [KeyUsage](x509_package_structs.md#struct-keyusage)

### prop notAfter

```cangjie
public prop notAfter: DateTime
```

Functionality: Parses the expiration time of the digital certificate's validity period.

Type: DateTime

### prop notBefore

```cangjie
public prop notBefore: DateTime
```

Functionality: Parses the start time of the digital certificate's validity period.

Type: DateTime

### prop publicKey

```cangjie
public prop publicKey: PublicKey
```

Functionality: Parses the public key from the digital certificate.

Type: [PublicKey](x509_package_interfaces.md#interface-publickey)

### prop publicKeyAlgorithm

```cangjie
public prop publicKeyAlgorithm: PublicKeyAlgorithm
```

Functionality: Parses the public key algorithm from the digital certificate.

Type: [PublicKeyAlgorithm](x509_package_enums.md#enum-publickeyalgorithm)

### prop serialNumber

```cangjie
public prop serialNumber: SerialNumber
```

Functionality: Parses the serial number of the digital certificate.

Type: [SerialNumber](x509_package_structs.md#struct-serialnumber)

### prop signature

```cangjie
public prop signature: Signature
```

Functionality: Parses the signature from the digital certificate.

Type: [Signature](x509_package_structs.md#struct-signature)

### prop signatureAlgorithm

```cangjie
public prop signatureAlgorithm: SignatureAlgorithm
```

Functionality: Parses the signature algorithm from the digital certificate.

Type: [SignatureAlgorithm](./x509_package_enums.md#enum-signaturealgorithm)

### prop subject

```cangjie
public prop subject: X509Name
```

Functionality: Parses the subject information from the digital certificate.

Type: [X509Name](x509_package_classes.md#class-x509name)

### init(X509CertificateInfo, X509Certificate, PublicKey, PrivateKey, ?SignatureAlgorithm)

```cangjie
public init(
    certificateInfo: X509CertificateInfo,
    parent!: X509Certificate,
    publicKey!: PublicKey,
    privateKey!: PrivateKey,
    signatureAlgorithm!: ?SignatureAlgorithm = None
)
```

Functionality: Creates a digital certificate object.

Parameters:

- certificateInfo: [X509CertificateInfo](x509_package_structs.md#struct-x509certificateinfo) - Digital certificate configuration information.
- parent!: [X509Certificate](x509_package_classes.md#class-x509certificate) - Issuer certificate.
- publicKey!: [PublicKey](x509_package_interfaces.md#interface-publickey) - Applicant's public key, only supports RSA, ECDSA, and DSA public keys.
- privateKey!: [PrivateKey](x509_package_interfaces.md#interface-privatekey) - Issuer's private key, only supports RSA, ECDSA, and DSA private keys.
- signatureAlgorithm!: ?[SignatureAlgorithm](./x509_package_enums.md#enum-signaturealgorithm) - Certificate signature algorithm. Default value is None. When using the default value, the default digest type is [SHA256](../../digest/digest_package_api/digest_package_classes.md#class-sha256).

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception when the public or private key type is unsupported, when the private key type does not match the private key type in the certificate signature algorithm, or when digital certificate information setup fails.

### static func decodeFromDer(DerBlob)

```cangjie
public static func decodeFromDer(der: DerBlob): X509Certificate
```

Functionality: Decodes a digital certificate in DER format.

Parameters:

- der: [DerBlob](x509_package_structs.md#struct-derblob) - Binary data in DER format.

Return Value:

- [X509Certificate](x509_package_classes.md#class-x509certificate) - Digital certificate decoded from DER format.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception when the data is empty or when the data is not in valid DER format for a digital certificate.

### static func decodeFromPem(String)

```cangjie
public static func decodeFromPem(pem: String): Array<X509Certificate>
```

Functionality: Decodes a digital certificate from PEM format.

Parameters:

- pem: String - Character stream of the digital certificate in PEM format.

Return Value:

- Array\<[X509Certificate](x509_package_classes.md#class-x509certificate)> - Array of digital certificates decoded from PEM format.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception when the character stream does not conform to PEM format or when the file header does not meet the digital certificate header standard.

### func encodeToDer()

```cangjie
public func encodeToDer(): DerBlob
```

Functionality: Encodes the digital certificate into DER format.

Return Value:

- [DerBlob](x509_package_structs.md#struct-derblob) - Encoded digital certificate in DER format.

### func encodeToPem()

```cangjie
public func encodeToPem(): PemEntry
```

Functionality: Encodes the digital certificate into PEM format.

Return Value:

- [PemEntry](x509_package_structs.md#struct-pementry) - Encoded digital certificate in PEM format.

### func hashCode()

```cangjie
public override func hashCode(): Int64
```

Functionality: Returns the hash value of the certificate.

Return Value:

- Int64 - Result obtained after performing a hash calculation on the certificate object.

### static func systemRootCerts()

```cangjie
public static func systemRootCerts(): Array<X509Certificate>
```

Functionality: Returns the operating system's root certificates, supporting Linux, macOS, and Windows platforms.

Return Value:

- Array\<[X509Certificate](x509_package_classes.md#class-x509certificate)> - The operating system's root certificate chain.

### func toString()

```cangjie
public override func toString(): String
```

Functionality: Generates a certificate name string, including the certificate's subject information, validity period, and issuer information.

Return Value:

- String - Certificate name string.

### func verify(VerifyOption)

```cangjie
public func verify(verifyOption: VerifyOption): Bool
```

Functionality: Verifies the current certificate's validity based on the verification option.

Verification Priority:1. Prioritize validating the expiration date;
2. Optionally validate the DNS domain name;
3. Finally, verify its validity based on the root certificate and intermediate certificates.

Parameters:

- verifyOption: [VerifyOption](x509_package_structs.md#struct-verifyoption) - Certificate verification options.

Return Value:

- Bool - Returns true if the certificate is valid, otherwise returns false.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception if verification fails due to internal errors such as memory allocation issues.

### operator func !=(X509Certificate)

```cangjie
public override operator func !=(other: X509Certificate): Bool
```

Function: Inequality comparison.

Parameters:

- other: [X509Certificate](x509_package_classes.md#class-x509certificate) - The certificate object to compare.

Return Value:

- Bool - Returns true if the certificates are different; otherwise, returns false.

### operator func ==(X509Certificate)

```cangjie
public override operator func ==(other: X509Certificate): Bool
```

Function: Equality comparison.

Parameters:

- other: [X509Certificate](x509_package_classes.md#class-x509certificate) - The certificate object to compare.

Return Value:

- Bool - Returns true if the certificates are identical; otherwise, returns false.

## class X509CertificateRequest

```cangjie
public class X509CertificateRequest <: Hashable & ToString {
    public init(
        privateKey: PrivateKey,
        certificateRequestInfo!: ?X509CertificateRequestInfo = None,
        signatureAlgorithm!: ?SignatureAlgorithm = None
    )
}
```

Function: Digital Certificate Signing Request (CSR).

Parent Types:

- Hashable
- ToString

### prop IPAddresses

```cangjie
public prop IPAddresses: Array<IP>
```

Function: Parses the IP addresses in the alternative names of the certificate signing request.

Type: Array\<[IP](x509_package_type.md#type-ip)>

### prop dnsNames

```cangjie
public prop dnsNames: Array<String>
```

Function: Parses the domain names in the alternative names of the certificate signing request.

Type: Array\<String>

### prop emailAddresses

```cangjie
public prop emailAddresses: Array<String>
```

Function: Parses the email addresses in the alternative names of the certificate signing request.

Type: Array\<String>

### prop publicKey

```cangjie
public prop publicKey: PublicKey
```

Function: Parses the public key in the certificate signing request.

Type: [PublicKey](x509_package_interfaces.md#interface-publickey)

### prop publicKeyAlgorithm

```cangjie
public prop publicKeyAlgorithm: PublicKeyAlgorithm
```

Function: Parses the public key algorithm in the certificate signing request.

Type: [PublicKeyAlgorithm](x509_package_enums.md#enum-publickeyalgorithm)

### prop signature

```cangjie
public prop signature: Signature
```

Function: Parses the signature in the certificate signing request.

Type: [Signature](x509_package_structs.md#struct-signature)

### prop signatureAlgorithm

```cangjie
public prop signatureAlgorithm: SignatureAlgorithm
```

Function: Parses the signature algorithm in the certificate signing request.

Type: [SignatureAlgorithm](./x509_package_enums.md#enum-signaturealgorithm)

### prop subject

```cangjie
public prop subject: X509Name
```

Function: Parses the subject information in the certificate signing request.

Type: [X509Name](x509_package_classes.md#class-x509name)

### init(PrivateKey, ?X509CertificateRequestInfo, ?SignatureAlgorithm)

```cangjie
public init(
    privateKey: PrivateKey,
    certificateRequestInfo!: ?X509CertificateRequestInfo = None,
    signatureAlgorithm!: ?SignatureAlgorithm = None
)
```

Function: Creates a certificate signing request object.

Parameters:

- privateKey: [PrivateKey](x509_package_interfaces.md#interface-privatekey) - Private key, supports only RSA, ECDSA, and DSA private keys.
- certificateRequestInfo!: ?[X509CertificateRequestInfo](x509_package_structs.md#struct-x509certificaterequestinfo) - Certificate signing request information, default value is None.
- signatureAlgorithm!: ?[SignatureAlgorithm](./x509_package_enums.md#enum-signaturealgorithm) - Certificate signature algorithm, default value is None. When using the default value, the default digest type is [SHA256](../../digest/digest_package_api/digest_package_classes.md#class-sha256).

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception if the private key type is unsupported, the private key type does not match the signature algorithm's private key type, or if setting the certificate signing request information fails.

### static func decodeFromDer(DerBlob)

```cangjie
public static func decodeFromDer(der: DerBlob): X509CertificateRequest
```

Function: Decodes a DER-format certificate signing request.

Parameters:

- der: [DerBlob](x509_package_structs.md#struct-derblob) - DER-format binary data.

Return Value:

- [X509CertificateRequest](x509_package_classes.md#class-x509certificaterequest) - The decoded certificate signing request from DER format.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception if the data is empty or not a valid DER-format certificate signing request.

### static func decodeFromPem(String)

```cangjie
public static func decodeFromPem(pem: String): Array<X509CertificateRequest>
```

Function: Decodes a PEM-format certificate signing request.

Parameters:

- pem: String - PEM-format certificate signing request character stream.

Return Value:

- Array\<[X509CertificateRequest](x509_package_classes.md#class-x509certificaterequest)> - The decoded array of certificate signing requests from PEM format.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception if the character stream is not in PEM format or if the file header does not meet the certificate signing request header standard.

### func encodeToDer()

```cangjie
public func encodeToDer(): DerBlob
```

Function: Encodes the certificate signing request into DER format.

Return Value:

- [DerBlob](x509_package_structs.md#struct-derblob) - The encoded DER-format certificate signing request.

### func encodeToPem()

```cangjie
public func encodeToPem(): PemEntry
```

Function: Encodes the certificate signing request into PEM format.

Return Value:

- [PemEntry](x509_package_structs.md#struct-pementry) - The encoded PEM-format certificate signing request.

### func hashCode()

```cangjie
public override func hashCode(): Int64
```

Function: Returns the hash value of the certificate signing request.

Return Value:

- Int64 - The hash computation result of the certificate signing request object.

### func toString()

```cangjie
public override func toString(): String
```

Function: Generates a certificate signing request name string, including the subject information.

Return Value:

- String - The certificate signing request name string.

## class X509Name

```cangjie
public class X509Name <: ToString {
    public init(
        countryName!: ?String = None,
        provinceName!: ?String = None,
        localityName!: ?String = None,
        organizationName!: ?String = None,
        organizationalUnitName!: ?String = None,
        commonName!: ?String = None,
        email!: ?String = None
    )
}
```

Function: The Distinguished Name (DN) of a certificate entity is a critical component of a digital certificate. It ensures the authenticity and trustworthiness of the certificate holder's identity and serves as an important basis for digital certificate verification.

[X509Name](x509_package_classes.md#class-x509name) typically includes the certificate entity's country or region name (Country Name), state or province name (State or Province Name), city name (Locality Name), organization name (Organization Name), organizational unit name (Organizational Unit Name), and common name (Common Name). It may also include an email address.

Parent Types:

- ToString

### prop commonName

```cangjie
public prop commonName: ?String
```

Function: Returns the common name of the certificate entity.

Type: ?String

### prop countryName

```cangjie
public prop countryName: ?String
```

Function: Returns the country or region name of the certificate entity.

Type: ?String

### prop email

```cangjie
public prop email: ?String
```

Function: Returns the email address of the certificate entity.

Type: ?String

### prop localityName

```cangjie
public prop localityName: ?String
```

Function: Returns the city name of the certificate entity.

Type: ?String

### prop organizationName

```cangjie
public prop organizationName: ?String
```

Function: Returns the organization name of the certificate entity.

Type: ?String

### prop organizationalUnitName

```cangjie
public prop organizationalUnitName: ?String
```

Function: Returns the organizational unit name of the certificate entity.

Type: ?String

### prop provinceName

```cangjie
public prop provinceName: ?String
```

Function: Returns the state or province name of the certificate entity.

Type: ?String

### init(?String, ?String, ?String, ?String, ?String, ?String, ?String)

```cangjie
    public init(
        countryName!: ?String = None,
        provinceName!: ?String = None,
        localityName!: ?String = None,
        organizationName!: ?String = None,
        organizationalUnitName!: ?String = None,
        commonName!: ?String = None,
        email!: ?String = None
    )
```

Function: Constructs an [X509Name](x509_package_classes.md#class-x509name) object.

Parameters:

- countryName!: ?String - Country or region name, default value is None.
- provinceName!: ?String - State or province name, default value is None.
- localityName!: ?String - City name, default value is None.
- organizationName!: ?String - Organization name, default value is None.
- organizationalUnitName!: ?String - Organizational unit name, default value is None.
- commonName!: ?String - Common name, default value is None.
- email!: ?String - Email address, default value is None.

Exceptions:

- [X509Exception](./x509_package_exceptions.md#class-x509exception) - Throws an exception if setting the certificate entity's distinguished name fails, such as internal errors like memory allocation exceptions.

### func toString()

```cangjie
public override func toString(): String
```

Function: Generates a string representation of the certificate entity name.

Return Value:

- String - The certificate entity name string, containing field information present in the entity name.