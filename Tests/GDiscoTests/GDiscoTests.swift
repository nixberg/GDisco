import XCTest
@testable import GDisco

final class GDiscoTests: XCTestCase {
    let iStatic = KeyPair()
    let rStatic = KeyPair()
    
    func greet(_ i: Handshake, _ r: Handshake, line: UInt = #line) {
        let a = i.finalize()
        let b = r.finalize()
        
        let m1 = "Hi, Bob!".data(using: .utf8)!
        let m2 = "Also ...".data(using: .utf8)!

        var e1 = Data()
        var e2 = Data()
        var d1 = Data()
        var d2 = Data()
        
        a.encrypt(plaintext: m1, into: &e1)
        a.encrypt(plaintext: m2, into: &e2)
        try! b.decrypt(ciphertext: e1, into: &d1)
        try! b.decrypt(ciphertext: e2, into: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
        
        e1.removeAll(keepingCapacity: true)
        e2.removeAll(keepingCapacity: true)
        d1.removeAll(keepingCapacity: true)
        d2.removeAll(keepingCapacity: true)
        
        b.encrypt(plaintext: m1, into: &e1)
        b.encrypt(plaintext: m2, into: &e2)
        try! a.decrypt(ciphertext: e1, into: &d1)
        try! a.decrypt(ciphertext: e2, into: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
    }
    
    func testK() {
        let initiator = Initiator.K(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.K(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
                
        greet(initiator, responder)
    }
    
    func testN() {
        let initiator = Initiator.N(their: rStatic.publicKey)
        let responder = Responder.N(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testX() {
        let initiator = Initiator.X(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.X(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testNNpsk2() {
        let psk = Data.random(count: 32)!
        
        let initiator = Initiator.NNpsk2(psk: psk)
        let responder = Responder.NNpsk2(psk: psk)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
        
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        initiator.read(from: networkBuffer)

        greet(initiator, responder)
    }
    
    func testKK() {
        let initiator = Initiator.KK(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.KK(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
        
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }

    func testNK() {
        let initiator = Initiator.NK(their: rStatic.publicKey)
        let responder = Responder.NK(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
     
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testNX() {
        let initiator = Initiator.NX()
        let responder = Responder.NX(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        responder.read(from: networkBuffer)
     
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testXX() {
        let initiator = Initiator.XX(my: iStatic)
        let responder = Responder.XX(my: rStatic)

        var networkBuffer = Data()
        initiator.firstWrite(to: &networkBuffer)
        responder.firstRead(from: networkBuffer)
     
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        networkBuffer.removeAll(keepingCapacity: true)
        initiator.secondWrite(to: &networkBuffer)
        try! responder.secondRead(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testIK() {
        let initiator = Initiator.IK(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.IK(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll(keepingCapacity: true)
        responder.write(to: &networkBuffer)
        initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    static var allTests = [
        ("K", testK),
        ("N", testN),
        ("X", testX),
        ("NNpsk2", testNNpsk2),
        ("KK", testKK),
        ("NK", testNK),
        ("NX", testNX),
        ("XX", testXX),
        ("IK", testIK),
    ]
}
