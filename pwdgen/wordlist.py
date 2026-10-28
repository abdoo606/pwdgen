"""A tiny built-in wordlist so the tool works offline.

Real passphrase security needs a large list (EFF's is 7776 words ≈ 12.9 bits/word).
This subset exists for tests and demos; the entropy maths is list-size agnostic.
"""

WORDS: tuple[str, ...] = tuple(
    """
    acorn amber anchor apple arrow aspen atlas autumn badge bamboo barrel basin
    beacon berry birch biscuit blizzard blossom bolt bottle bramble breeze bridge
    bronze bubble bucket butter cabin cactus candle canyon carbon carpet cedar
    chalk cherry cider cipher cliff cloud clover cobalt comet copper coral cotton
    crimson crystal cypress dawn delta desert diamond dolphin drift drizzle echo
    ember falcon feather fern fable flint forest fossil fountain frost galaxy
    garden garnet ginger glacier granite gravel harbor harvest hazel heather
    hollow honey horizon iceberg indigo island ivory jade jasper jungle juniper
    kettle lantern lava lemon lilac linen lizard lotus lunar maple marble meadow
    mercury mint mirror mist mosaic moss nectar nickel nightingale north nutmeg
    oak oasis ocean olive onyx opal orbit orchid otter pebble pepper petal pilot
    pine plum pollen pond prairie prism quartz quill rain raven reef ridge river
    robin rocket rosemary ruby saffron sage sapphire shadow silver sky slate
    snow solar sparrow spice spruce star stone storm summit sunset thistle thunder
    tidal timber topaz torch tulip tundra umber valley velvet violet walnut willow
    winter wolf yarrow zephyr zinc
    """.split()
)

assert len(WORDS) == len(set(WORDS)), "wordlist must not contain duplicates"
