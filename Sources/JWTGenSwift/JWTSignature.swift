import Foundation
import Security

/// A utility for creating a digital signature for JWTs (JSON Web Tokens) using RSA algorithms.
enum JWTSignature {

    /// Creates a digital signature for the provided data using the specified signing algorithm and private key.
    ///
    /// The method selects the appropriate signature algorithm based on the `SigningAlgorithm` and uses the `SecKeyCreateSignature` function to sign the data.
    ///
    /// - Parameters:
    ///   - data: The data to sign, typically the concatenation of the JWT header and payload.
    ///   - algorithm: The signing algorithm to use.
    ///   - key: The private key used for creating the signature.
    /// - Returns: The signature as a `Data` object.
    static func create(
        from data: Data,
        algorithm: SigningAlgorithm,
        key: SecKey
    ) throws -> Data {
        let secKeyAlgorithm: SecKeyAlgorithm

        switch algorithm {
        case .RS1:
            secKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
        case .RS224:
            secKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA224
        case .RS256:
            secKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        case .RS384:
            secKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA384
        case .RS512:
            secKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
        }

        guard let signature = SecKeyCreateSignature(key, secKeyAlgorithm, data as CFData, nil) as Data? else {
            throw Error.invalidSignature
        }

        return signature
    }
}

extension JWTSignature {
    /// Errors that can occur during the signature creation process.
    enum Error: Swift.Error {
        /// Thrown when the digital signature creation fails.
        case invalidSignature
    }
}
