import Foundation

/// A utility for encoding various components of a JWT (JSON Web Token).
enum JWTEncoder {

    /// Encodes the JWT header into a Base64URL-encoded string.
    ///
    /// The header is first converted to a dictionary, with the algorithm and type added.
    /// The dictionary is then serialized to JSON and encoded using Base64URL.
    ///
    /// - Parameter header: The JWT header object to encode.
    /// - Returns: A Base64URL-encoded string of the JWT header.
    static func encode(header: JWTHeader) throws -> String {
        var headerDictionary = header.extra
        headerDictionary["alg"] = header.algorithm.rawValue
        headerDictionary["typ"] = header.type

        guard let headerData = try? JSONSerialization.data(withJSONObject: headerDictionary, options: []) else {
            throw Error.invalidHeader
        }

        return base64EncodedString(from: headerData)
    }

    /// Encodes the JWT payload into a Base64URL-encoded string.
    ///
    /// The payload is first encoded into JSON using a `JSONEncoder` with the
    /// date encoding strategy set to `.secondsSince1970`, and then Base64URL-encoded.
    ///
    /// - Parameter payload: The encodable object representing the JWT payload.
    /// - Throws: `JWTEncoder.Error.invalidPayload` if the payload can't be serialized.
    /// - Returns: A Base64URL-encoded string of the JWT payload.
    static func encode(payload: Encodable) throws -> String {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970

        guard let payloadData = try? jsonEncoder.encode(payload) else {
            throw Error.invalidPayload
        }

        return base64EncodedString(from: payloadData)
    }

    /// Encodes the JWT signature into a Base64URL-encoded string.
    ///
    /// - Parameter signature: The binary signature data to encode.
    /// - Returns: A Base64URL-encoded string of the JWT signature.
    static func encode(signature: Data) -> String {
        return base64EncodedString(from: signature)
    }

    /// Encodes the provided data into a Base64URL-encoded string.
    ///
    /// Replaces the `+` and `/` characters with `-` and `_` respectively, and removes
    /// padding `=` characters to conform to the Base64URL format.
    ///
    /// - Parameter data: The binary data to encode.
    /// - Returns: A Base64URL-encoded string.
    private static func base64EncodedString(from data: Data) -> String {
        var base64EncodedString = data.base64EncodedString()
        base64EncodedString = base64EncodedString.replacingOccurrences(of: "+", with: "-")
        base64EncodedString = base64EncodedString.replacingOccurrences(of: "/", with: "_")
        base64EncodedString = base64EncodedString.replacingOccurrences(of: "=", with: "")
        return base64EncodedString
    }
}

extension JWTEncoder {
    /// Errors that can occur during JWT encoding.
    enum Error: Swift.Error {
        /// Thrown when the JWT header can't be serialized to JSON.
        case invalidHeader
        /// Thrown when the JWT payload can't be serialized to JSON.
        case invalidPayload
    }
}
