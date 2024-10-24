import Foundation

/// Generates a JWT (JSON Web Token) by encoding the header, payload, and signing them using an RSA private key.
public enum JWTGenerator {
    /// Generates a JWT by encoding the provided header, payload, and signing them using the provided private key.
    ///
    /// The header and payload are first Base64URL-encoded, then concatenated into a single string.
    /// This string is signed using the RSA private key, and the signature is also Base64URL-encoded.
    /// The final JWT is returned in the format `header.payload.signature`.
    ///
    /// - Parameters:
    ///   - header: The JWT header to encode, which contains metadata about the JWT.
    ///   - payload: The payload to encode, containing the claims or data in the JWT.
    ///   - privateKey: The RSA private key used to sign the JWT.
    /// - Returns: The final JWT as a string, in the format `header.payload.signature`.
    public static func generateJWT(
        header: JWTHeader,
        payload: Encodable,
        privateKey: RSAPrivateKey
    ) throws -> String {
        let encodedHeader = try JWTEncoder.encode(header: header)
        let encodedPayload = try JWTEncoder.encode(payload: payload)

        guard let headerAndPayloadData = "\(encodedHeader).\(encodedPayload)".data(using: .utf8) else {
            throw Error.invalidHeaderOrPayload
        }

        let signature = try JWTSignature.create(
            from: headerAndPayloadData,
            algorithm: header.algorithm,
            key: privateKey.secKey
        )
        let encodedSignature = JWTEncoder.encode(signature: signature)

        return "\(encodedHeader).\(encodedPayload).\(encodedSignature)"
    }
}

extension JWTGenerator {
    /// Errors that can occur during JWT generation.
    enum Error: Swift.Error {
        /// Thrown when the encoded header and payload cannot be converted to `Data`.
        case invalidHeaderOrPayload
    }
}
