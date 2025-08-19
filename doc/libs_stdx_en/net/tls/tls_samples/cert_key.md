# Server Certificate and Public Key in a Single File

> **Note:**
>
> You need to prepare the certificate file yourself.

Example:

<!-- compile -->
```cangjie
import std.io.*
import std.{fs.*, collection.*}
import stdx.net.tls.*
import stdx.crypto.x509.{X509Certificate, PrivateKey, Pem, PemEntry, DerBlob}

let certificatePath = "/etc/myserver/cert-and-key.pem"

func parsePem(text: String): (Array<X509Certificate>, PrivateKey) {
    let pem = Pem.decode(text)
    let chain = pem |> filter<PemEntry> {entry => entry.label == PemEntry.LABEL_CERTIFICATE} |>
        map<PemEntry, X509Certificate> {entry => X509Certificate.decodeFromDer(entry.body ?? DerBlob())} |> collectArray

    let key = (pem |> filter<PemEntry> {entry => entry.label == PemEntry.LABEL_PRIVATE_KEY} |>
        map<PemEntry, PrivateKey> {entry => PrivateKey.decodeDer(entry.body ?? DerBlob())} |> first) ?? throw Exception(
        "No private key found in the PEM file")

    if (chain.isEmpty()) {
        throw Exception("No certificates found in the PEM file")
    }

    return (chain, key)
}

func readTextFromFile(path: String): String {
    var fileString = ""
    try (file = File(path, Read)) {
        fileString = String.fromUtf8(readToEnd(file))
        ()
    }
    fileString
}

main() {
    // Parse certificate and private key
    let pem = readTextFromFile(certificatePath)

    let (certificate, privateKey) = parsePem(pem)

    var _ = TlsServerConfig(certificate, privateKey)

    // For HTTPS service, please refer to other server examples
}
```