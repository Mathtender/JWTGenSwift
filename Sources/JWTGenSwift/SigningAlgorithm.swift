/// Enum representing the supported signing algorithms for JWTs.
public enum SigningAlgorithm: String, Codable {
    /// RSA with SHA-256 hashing (commonly used).
    case RS256
    /// RSA with SHA-384 hashing.
    case RS384
    /// RSA with SHA-512 hashing.
    case RS512
}
