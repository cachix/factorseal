import Foundation

/// A deliberately narrow export projection. Only FactorSeal's own metadata may
/// be omitted, and the caller must obtain consent before using the projection.
public struct SystemExport {
    public let data: Data
    public let omittedExtensions: Int

    public init(_ source: Data) throws {
        guard source.count <= 128 * 1024 * 1024 else { throw CXFCodec.Failure.payloadTooLarge }
        let root = try JSONSerialization.jsonObject(with: source)
        var count = 0
        func project(_ value: Any) -> Any {
            if let array = value as? [Any] { return array.map(project) }
            guard var object = value as? [String: Any] else { return value }
            if let extensions = object["extensions"] as? [[String: Any]] {
                let retained = extensions.filter { entry in
                    let name = entry["name"] as? String
                    let version = entry["version"] as? Int
                    let own = (name == "org.factorseal.item" && (version == 1 || version == 2))
                        || (name == "org.factorseal.field" && version == 1)
                    if own { count += 1 }
                    return !own
                }
                if retained.isEmpty { object.removeValue(forKey: "extensions") }
                else { object["extensions"] = retained }
            }
            return object.mapValues(project)
        }
        data = try JSONSerialization.data(withJSONObject: project(root), options: [.sortedKeys])
        omittedExtensions = count
        // All other source properties still have to survive the SDK mapping.
        _ = try CXFCodec.decode(data)
    }
}
