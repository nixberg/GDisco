import Foundation

// First character:
//  N = No static key for initiator
//  K = Static key for initiator Known to responder
//  X = Static key for initiator Xmitted ("transmitted") to responder
//  I = Static key for initiator Immediately transmitted to responder
//
// Second character:
//  N = No static key for responder
//  K = Static key for responder Known to initiator
//  X = Static key for responder Xmitted ("transmitted") to initiator

// K:
//  -> s
//  <- s
//  ...
//  -> e, es, ss

extension Handshake.I {
    public static func K(my s: KeyPair, their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("K", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
                $0.mixKey(s.DH(their: rs))
            })
        ])
    }
}

extension Handshake.R {
    public static func K(my s: KeyPair, their rs: PublicKey) -> Handshake {
        return Handshake("K", .responder, [
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(s.DH(their: re))
                $0.mixKey(s.DH(their: rs))
            })
        ])
    }
}


// N:
//  <- s
//  ...
//  -> e, es

extension Handshake.I {
    public static func N(their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("N", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
            })
        ])
    }
}

extension Handshake.R {
    public static func N(my s: KeyPair) -> Handshake {
        return Handshake("N", .responder, [
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(s.DH(their: re))
            })
        ])
    }
}


// X:
//  <- s
//  ...
//  -> e, es, s, ss

extension Handshake.I {
    public static func X(my s: KeyPair, their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("X", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
                $0.encryptAndHash(s.publicKey.data, into: &$1)
                $0.mixKey(s.DH(their: rs))
            })
        ])
    }
}

extension Handshake.R {
    public static func X(my s: KeyPair) -> Handshake {
        return Handshake("X", .responder, [
            .readStatic({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(s.DH(their: re))
                let rs = try PublicKey(from: try $0.decryptAndHash($1.advanced(by: 32)))
                $0.mixKey(s.DH(their: rs))
                return (64, rs)
            })
        ])
    }
}


// NNpsk2:
//  -> e
//  <- e, ee, psk

extension Handshake.I {
    public static func NNpsk2(psk: Data) -> Handshake {
        let e = KeyPair()
        return Handshake("NNpsk2", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
            }),
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(e.DH(their: re))
                $0.mixKey(psk)
            })
        ])
    }
}

extension Handshake.R {
    public static func NNpsk2(psk: Data) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("NNpsk2", .responder, [
            .read({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
                $0.mixKey(psk)
            })
        ])
    }
}


// KK:
//  -> s
//  <- s
//  ...
//  -> e, es, ss
//  <- e, ee, se

extension Handshake.I {
    public static func KK(my s: KeyPair, their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("KK", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
                $0.mixKey(s.DH(their: rs))
            }),
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(e.DH(their: re))
                $0.mixKey(s.DH(their: re))
            })
        ])
    }
}

extension Handshake.R {
    public static func KK(my s: KeyPair, their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("KK", .responder, [
            .read({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
                $0.mixKey(s.DH(their: re!))
                $0.mixKey(s.DH(their: rs))
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
                $0.mixKey(e.DH(their: rs))
            })
        ])
    }
}


// NK:
//  <- s
//  ...
//  -> e, es
//  <- e, ee

extension Handshake.I {
    public static func NK(their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("NK", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
            }),
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(e.DH(their: re))
            })
        ])
    }
}

extension Handshake.R {
    public static func NK(my s: KeyPair) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("NK", .responder, [
            .read({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
                $0.mixKey(s.DH(their: re!))
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
            })
        ])
    }
}


// NX:
//  -> e
//  <- e, ee, s, es

extension Handshake.I {
    public static func NX() -> Handshake {
        let e = KeyPair()
        return Handshake("NX", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
            }),
            .readStatic({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(e.DH(their: re))
                let rs = try PublicKey(from: try $0.decryptAndHash($1.advanced(by: 32)))
                $0.mixKey(e.DH(their: rs))
                return (64, rs)
            })
        ])
    }
}

extension Handshake.R {
    public static func NX(my s: KeyPair) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("NX", .responder, [
            .read({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
                $0.encryptAndHash(s.publicKey.data, into: &$1)
                $0.mixKey(s.DH(their: re!))
            })
        ])
    }
}


// NX:
//  -> e
//  <- e, ee, s, es
//  -> s, se

extension Handshake.I {
    public static func XX(my s: KeyPair) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("XX", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
            }),
            .readStatic({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
                $0.mixKey(e.DH(their: re!))
                let rs = try PublicKey(from: try $0.decryptAndHash($1.advanced(by: 32)))
                $0.mixKey(e.DH(their: rs))
                return (64, rs)
            }),
            .write({
                $0.encryptAndHash(s.publicKey.data, into: &$1)
                $0.mixKey(s.DH(their: re!))
            }),
        ])
    }
}

extension Handshake.R {
    public static func XX(my s: KeyPair) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        return Handshake("XX", .responder, [
            .read({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
                $0.encryptAndHash(s.publicKey.data, into: &$1)
                $0.mixKey(s.DH(their: re!))
            }),
            .readStatic({
                let rs = try PublicKey(from: try $0.decryptAndHash($1))
                $0.mixKey(e.DH(their: rs))
                return (32, rs)
            }),
        ])
    }
}


// IK:
//  <- s
//  ...
//  -> e, es, s, ss
//  <- e, ee, se

extension Handshake.I {
    public static func IK(my s: KeyPair, their rs: PublicKey) -> Handshake {
        let e = KeyPair()
        return Handshake("IK", .initiator, [
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: rs))
                $0.encryptAndHash(s.publicKey.data, into: &$1)
                $0.mixKey(s.DH(their: rs))
            }),
            .read({
                let re = try PublicKey(from: $1)
                $0.mixHash(re.data)
                $0.mixKey(e.DH(their: re))
                $0.mixKey(s.DH(their: re))
            })
        ])
    }
}

extension Handshake.R {
    public static func IK(my s: KeyPair) -> Handshake {
        let e = KeyPair()
        var re: PublicKey? = nil
        var rs: PublicKey? = nil
        return Handshake("IK", .responder, [
            .readStatic({
                re = try PublicKey(from: $1)
                $0.mixHash(re!.data)
                $0.mixKey(s.DH(their: re!))
                rs = try PublicKey(from: try $0.decryptAndHash($1.advanced(by: 32)))
                $0.mixKey(s.DH(their: rs!))
                return (64, rs!)
            }),
            .write({
                $1.append(e.publicKey.data)
                $0.mixHash(e.publicKey.data)
                $0.mixKey(e.DH(their: re!))
                $0.mixKey(e.DH(their: rs!))
            })
        ])
    }
}
