/// Represents the header of a JWT (JSON Web Token).
///
/// The header typically contains information about the type of token and the algorithm used
/// for signing the token. Additional fields can be added using the `extra` dictionary.
public struct JWTHeader {
    /// The type of the token, which is typically "JWT".
    let type: String

    /// The signing algorithm used for the token.
    let algorithm: SigningAlgorithm

    /// A dictionary of extra fields to include in the header, such as custom claims.
    let extra: [String: String]

    /// Initializes a new `JWTHeader` with a signing algorithm and optional extra fields.
    ///
    /// The `type` is automatically set to "JWT", and additional fields can be provided
    /// using the `extra` dictionary. This allows for customization of the header.
    ///
    /// - Parameters:
    ///   - type: The type of the token. Defaults to `JWT`.
    ///   - algorithm: The signing algorithm used for the JWT.
    ///   - extra: A dictionary of extra fields to include in the header. Defaults to an empty dictionary.
    public init(
        type: String = "JWT",
        algorithm: SigningAlgorithm,
        extra: [String: String] = [:]
    ) {
        self.type = type
        self.algorithm = algorithm
        self.extra = extra
    }
}
