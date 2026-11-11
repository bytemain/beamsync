import { blake3Hex, utf8Bytes } from "./crypto.js";

const WORDS_256 = [
  "amber", "anchor", "apple", "arctic", "arrow", "atlas", "autumn", "avalon",
  "badger", "bamboo", "beacon", "bison", "blade", "breeze", "bridge", "bronze",
  "cabin", "cactus", "camera", "candle", "canyon", "carbon", "castle", "cedar",
  "chalk", "cherry", "cipher", "citrus", "cliff", "cloud", "cobalt", "comet",
  "compass", "copper", "coral", "cosmos", "cotton", "crane", "creek", "crown",
  "crystal", "cypress", "dagger", "dawn", "delta", "desert", "dolphin", "dragon",
  "drift", "dune", "eagle", "echo", "eclipse", "ember", "emerald", "engine",
  "epoch", "falcon", "feather", "fern", "field", "fjord", "flame", "flint",
  "forest", "forge", "fossil", "frost", "galaxy", "garden", "garnet", "geyser",
  "glacier", "globe", "granite", "grove", "harbor", "harvest", "hawk", "hazel",
  "hearth", "helium", "heron", "horizon", "hunter", "iceberg", "indigo", "island",
  "ivory", "jacket", "jade", "jaguar", "jasper", "jet", "jungle", "juniper",
  "karma", "kestrel", "kernel", "lagoon", "lantern", "laurel", "lava", "ledger",
  "lemon", "linen", "lion", "lotus", "lunar", "lynx", "magnet", "maple",
  "marble", "marine", "meadow", "mercury", "meteor", "mirror", "mist", "monarch",
  "moss", "mountain", "nebula", "nectar", "nickel", "nimbus", "noble", "north",
  "nova", "nutmeg", "oasis", "obsidian", "ocean", "olive", "onyx", "opal",
  "orbit", "orchid", "origin", "osprey", "otter", "oxygen", "pacific", "palace",
  "panda", "panther", "paper", "pebble", "pelican", "pepper", "phoenix", "photon",
  "pillar", "pine", "pioneer", "planet", "plasma", "plume", "polar", "poplar",
  "portal", "prairie", "prism", "pulsar", "quartz", "quest", "quiver", "radar",
  "rain", "ranger", "rapid", "raven", "reef", "relay", "ridge", "ripple",
  "river", "robin", "rocket", "ruby", "saddle", "saffron", "sailor", "salmon",
  "sandal", "sapphire", "saturn", "scarlet", "scooter", "sector", "sequoia", "shadow",
  "shield", "sierra", "signal", "silica", "silver", "skyline", "slate", "solar",
  "solstice", "sonar", "spark", "sparrow", "spectrum", "sphinx", "spruce", "starlight",
  "steam", "steel", "stone", "storm", "stream", "summit", "sunrise", "sunset",
  "swift", "switch", "talon", "tango", "temple", "terra", "thistle", "thunder",
  "tiger", "timber", "titan", "topaz", "torch", "torrent", "tower", "trail",
  "trident", "tropic", "tundra", "tunnel", "turbine", "turtle", "twilight", "umber",
  "valley", "vapor", "velvet", "vector", "vertex", "vessel", "violet", "vortex",
  "voyage", "walnut", "wave", "willow", "wind", "winter", "xenon", "zephyr"
] as const;

export interface ParsedPairingPhrase {
  slotCode: string;
  secretPhrase: string;
  normalized: string;
}

export function generateSecretWords(randomBytes: Uint8Array, wordCount = 3): string {
  if (randomBytes.length < wordCount) {
    throw new Error(`Expected at least ${wordCount} random bytes`);
  }
  const picked: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    picked.push(WORDS_256[randomBytes[i] & 0xff]);
  }
  return picked.join("-");
}

export function deriveRendezvousSlot(customPhrase: string): {
  slotCode: string;
  secretPhrase: string;
} {
  const normalized = customPhrase.trim().toLowerCase().replace(/\s+/g, "-");
  if (normalized.length < 3) {
    throw new Error("Custom pairing phrase must be at least 3 characters");
  }
  const slotCode =
    "k" + blake3Hex(utf8Bytes(`beamsync/rendezvous/v1:${normalized}`)).slice(0, 15);
  return { slotCode, secretPhrase: normalized };
}

export function formatPairingPhrase(slotCode: string, secretWords: string): string {
  return `${slotCode.trim().toLowerCase()}-${secretWords.trim().toLowerCase()}`;
}

export function parsePairingPhrase(raw: string): ParsedPairingPhrase {
  const cleaned = raw.trim().toLowerCase().replace(/\s+/g, "-");
  if (cleaned.length < 3) {
    throw new Error("Pairing phrase must be at least 3 characters");
  }
  const numericSlotMatch = /^([0-9]+)-(.+)$/.exec(cleaned);
  if (numericSlotMatch) {
    const slotCode = numericSlotMatch[1];
    const secretPhrase = numericSlotMatch[2];
    if (secretPhrase.length < 3) {
      throw new Error("Invalid pairing phrase secret component");
    }
    return {
      slotCode,
      secretPhrase,
      normalized: `${slotCode}-${secretPhrase}`,
    };
  }

  // Symmetric user-supplied phrase (e.g. `dragon-coffee-99` or single secret token):
  // derive a blinded rendezvous slot so the server never learns the secret phrase.
  const { slotCode, secretPhrase } = deriveRendezvousSlot(cleaned);
  return {
    slotCode,
    secretPhrase,
    normalized: cleaned,
  };
}
