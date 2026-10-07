import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("GeneratorModel")
struct GeneratorModelTests {
    private func makeModel() -> GeneratorModel {
        GeneratorModel(service: PreviewVaultService(unlocked: true))
    }

    @Test("a random password has 24 characters and a strength")
    func random() async {
        let model = makeModel()
        await model.regenerate()
        #expect(model.value.count == 24)
        #expect(model.bits > 0)
        #expect(model.strength?.bits == model.bits)
        #expect(model.generation == 1)
        #expect(model.error == nil)
    }

    @Test("each regenerate bumps the generation")
    func generation() async {
        let model = makeModel()
        await model.regenerate()
        await model.regenerate()
        #expect(model.generation == 2)
    }

    @Test("a PIN has six digits")
    func pin() async {
        let model = makeModel()
        model.setStyle(.pin)
        #expect(model.options.length == 6)
        await model.regenerate()
        #expect(model.value.count == 6)
        #expect(model.value.allSatisfy { $0.isASCII && $0.isNumber })
    }

    @Test("a memorable password joins words with the separator")
    func memorable() async {
        let model = makeModel()
        model.setStyle(.memorable)
        model.options.separator = "."
        await model.regenerate()
        #expect(model.value.split(separator: ".").count == model.options.words)
    }

    @Test("changing the style back sets the default length of that style")
    func styleLength() {
        let model = makeModel()
        model.setStyle(.pin)
        model.setStyle(.random)
        #expect(model.options.length == 24)
    }

    @Test("the length stays in the range of the style")
    func lengthClamps() {
        let model = makeModel()
        model.length = 100
        #expect(model.options.length == 64)
        model.length = 2
        #expect(model.options.length == 8)
        model.setStyle(.pin)
        model.length = 100
        #expect(model.options.length == 12)
        model.length = 2
        #expect(model.options.length == 4)
        #expect(model.length == 4)
    }

    @Test("clear drops the value")
    func clear() async {
        let model = makeModel()
        await model.regenerate()
        model.clear()
        #expect(model.value.isEmpty)
        #expect(model.bits == 0)
        #expect(model.strength == nil)
    }

    @Test("the score comes from the bits, and from the core only when the bits are unknown")
    func score() {
        #expect(GeneratorModel.score(bits: 27.9, fallback: 2) == 0)
        #expect(GeneratorModel.score(bits: 28, fallback: 2) == 1)
        #expect(GeneratorModel.score(bits: 35.9, fallback: 2) == 1)
        #expect(GeneratorModel.score(bits: 36, fallback: 0) == 2)
        #expect(GeneratorModel.score(bits: 59.9, fallback: 0) == 2)
        #expect(GeneratorModel.score(bits: 60, fallback: 0) == 3)
        #expect(GeneratorModel.score(bits: 79.9, fallback: 0) == 3)
        #expect(GeneratorModel.score(bits: 80, fallback: 0) == 4)
        #expect(GeneratorModel.score(bits: 0, fallback: 2) == 2)
    }
}
