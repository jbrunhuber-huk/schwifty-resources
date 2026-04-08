//
//  CertificateServerTrustEvaluator.swift
//
//  Copyright (c) 2023 HUK-COBURG
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

import Foundation

/// Evaluates server trust by pinning DER-encoded certificates as anchor certificates.
///
/// Provide the certificates at initialization, either directly or via the convenience
/// initializer that looks them up from `CertificatePinningRegistry`.
///
/// Marked `@unchecked Sendable` because `SecCertificate` (a Core Foundation type) is
/// immutable and thread-safe but not formally marked `Sendable` by the SDK.
public struct CertificateServerTrustEvaluator: ServerTrustEvaluating {
    private let certificates: [SecCertificate]

    /// Creates an evaluator that pins the given certificates.
    public init(certificates: [SecCertificate]) {
        self.certificates = certificates
    }

    /// Creates an evaluator using certificates currently registered in
    /// `CertificatePinningRegistry` for the given host.
    @CertificatePinningActor
    @available(*, deprecated, message: "Use ServerTrustRegistry with CertificateServerTrustEvaluator(certificates:) instead.")
    public init(for host: String) {
        self.certificates = CertificatePinningRegistry.sharedInstance.registeredCertificates(for: host) ?? []
    }

    public func evaluate(_ serverTrust: SecTrust, for host: String) throws -> Bool {
        guard !certificates.isEmpty else {
            return false
        }

        let status = SecTrustSetAnchorCertificates(serverTrust, certificates as NSArray)
        guard status == errSecSuccess else {
            return false
        }

        var error: CFError?
        let trusted = SecTrustEvaluateWithError(serverTrust, &error)
        if let error { throw error as Error }
        return trusted
    }
}
