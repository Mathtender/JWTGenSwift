import Foundation

/// A structure representing an RSA private key, used for signing JWTs.
public struct RSAPrivateKey {

    /// The `SecKey` object representing the private key.
    let secKey: SecKey

    /// Initializes an `RSAPrivateKey` from a PEM-formatted string.
    ///
    /// The PEM string is stripped of headers, footers, and formatting, then converted to DER format.
    /// The resulting data is used to create an RSA private key using the `SecKey` API.
    ///
    /// - Parameter pemKey: A PEM-formatted string representing the private key.
    public init(pemKey: String) throws {
        let keyData = try Self.strip(pemKey: pemKey)
        let sizeInBits = keyData.count * MemoryLayout<UInt8>.size
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
        ]

        guard let secKey = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
            throw Error.invalidPrivateKey
        }

        self.secKey = secKey
    }

    /// Strips the PEM headers and footers, and converts the PEM string to DER format.
    ///
    /// The method removes the "BEGIN" and "END" headers from the PEM string, filters out any
    /// whitespace or line breaks, and then decodes the base64-encoded key to binary DER format.
    ///
    /// - Parameter pemKey: The PEM-formatted private key string.
    /// - Returns: The binary DER representation of the private key.
    private static func strip(pemKey: String) throws -> Data {
        // Remove all whitespace and newlines from the PEM string.
        let strippedKey = String(pemKey.filter { !" \n\t\r".contains($0) })

        // Split the PEM string by "-----" to extract the base64-encoded key.
        let pemComponents = strippedKey.components(separatedBy: "-----")

        // Ensure the PEM string contains the expected headers and footers.
        guard pemComponents.count >= 5 else {
            throw Error.missingPEMHeaders
        }

        // Decode the base64-encoded key into binary DER format.
        guard let derKey = Data(base64Encoded: pemComponents[2]) else {
            throw Error.invalidPrivateKey
        }

        // Check if the DER key contains padding or other metadata and strip it.
        if derKey[26] == 0x30 {
            return derKey.advanced(by: 26)
        } else {
            return derKey
        }
    }
}

extension RSAPrivateKey {
    /// Errors that can occur when working with RSA private keys.
    enum Error: Swift.Error {
        /// Thrown when the PEM string is missing the "BEGIN" and "END" headers.
        case missingPEMHeaders
        /// Thrown when the private key is invalid or cannot be created.
        case invalidPrivateKey
    }
}
