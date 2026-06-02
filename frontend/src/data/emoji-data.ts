// MSG-006: Static emoji dataset (curated subset of Unicode CLDR data).
//
// This is a hand-curated, categorized dataset covering all 9 categories with
// shortcodes, names, keywords and skin-tone support flags. It is intentionally
// a representative subset (not the full ~1800-entry Unicode set) so the bundle
// stays small and `tsc` stays fast; the structure matches the full dataset so
// it can be swapped for a generated file later without changing consumers.

export type EmojiCategory =
  | "smileys"
  | "people"
  | "animals"
  | "food"
  | "travel"
  | "activities"
  | "objects"
  | "symbols"
  | "flags";

export interface EmojiEntry {
  emoji: string; // Unicode character(s), e.g. "😄"
  shortcode: string; // e.g. "smile"
  name: string; // e.g. "Smiling Face with Open Mouth"
  keywords: string[]; // e.g. ["happy", "joy", "laugh"]
  category: EmojiCategory;
  skinToneSupport: boolean;
  version: string; // Unicode version, e.g. "6.0"
}

export interface SkinTone {
  id: string;
  label: string;
  modifier: string;
}

export const EMOJI_CATEGORIES: { id: EmojiCategory; label: string; icon: string }[] = [
  { id: "smileys", label: "Smileys & Emotion", icon: "😀" },
  { id: "people", label: "People & Body", icon: "👋" },
  { id: "animals", label: "Animals & Nature", icon: "🐾" },
  { id: "food", label: "Food & Drink", icon: "🍕" },
  { id: "travel", label: "Travel & Places", icon: "✈️" },
  { id: "activities", label: "Activities", icon: "⚽" },
  { id: "objects", label: "Objects", icon: "💡" },
  { id: "symbols", label: "Symbols", icon: "❤️" },
  { id: "flags", label: "Flags", icon: "🏁" },
];

export const SKIN_TONES: SkinTone[] = [
  { id: "default", label: "Default", modifier: "" },
  { id: "light", label: "Light", modifier: "\u{1F3FB}" },
  { id: "medium-light", label: "Medium-Light", modifier: "\u{1F3FC}" },
  { id: "medium", label: "Medium", modifier: "\u{1F3FD}" },
  { id: "medium-dark", label: "Medium-Dark", modifier: "\u{1F3FE}" },
  { id: "dark", label: "Dark", modifier: "\u{1F3FF}" },
];

/**
 * Apply a skin-tone modifier to an emoji. The modifier codepoint is inserted
 * after the first (base) codepoint. Emojis without skin-tone support and the
 * empty (default) modifier are returned unchanged.
 */
export function applySkinTone(emoji: string, modifier: string): string {
  if (!modifier) return emoji;
  const codepoints = [...emoji];
  if (codepoints.length === 0) return emoji;
  return codepoints[0] + modifier + codepoints.slice(1).join("");
}

// Compact tuple form keeps the source readable: [emoji, shortcode, name, keywords, skinTone]
type Row = [string, string, string, string[], boolean?];

function build(category: EmojiCategory, rows: Row[], version = "6.0"): EmojiEntry[] {
  return rows.map(([emoji, shortcode, name, keywords, skin]) => ({
    emoji,
    shortcode,
    name,
    keywords,
    category,
    skinToneSupport: !!skin,
    version,
  }));
}

const SMILEYS = build("smileys", [
  ["😀", "grinning", "Grinning Face", ["happy", "smile", "joy"]],
  ["😃", "smiley", "Grinning Face with Big Eyes", ["happy", "joy", "haha"]],
  ["😄", "smile", "Smiling Face with Open Mouth", ["happy", "joy", "laugh"]],
  ["😁", "grin", "Beaming Face", ["happy", "smile"]],
  ["😆", "laughing", "Grinning Squinting Face", ["happy", "haha", "laugh"]],
  ["😅", "sweat_smile", "Grinning Face with Sweat", ["hot", "relief"]],
  ["🤣", "rofl", "Rolling on the Floor Laughing", ["lol", "laugh", "funny"]],
  ["😂", "joy", "Face with Tears of Joy", ["lol", "laugh", "cry", "funny"]],
  ["🙂", "slightly_smiling_face", "Slightly Smiling Face", ["smile"]],
  ["🙃", "upside_down_face", "Upside-Down Face", ["silly", "sarcasm"]],
  ["😉", "wink", "Winking Face", ["flirt", "wink"]],
  ["😊", "blush", "Smiling Face with Smiling Eyes", ["happy", "shy"]],
  ["😇", "innocent", "Smiling Face with Halo", ["angel", "innocent"]],
  ["🥰", "smiling_face_with_three_hearts", "Smiling Face with Hearts", ["love", "adore"]],
  ["😍", "heart_eyes", "Smiling Face with Heart-Eyes", ["love", "crush"]],
  ["🤩", "star_struck", "Star-Struck", ["wow", "amazing"]],
  ["😘", "kissing_heart", "Face Blowing a Kiss", ["love", "kiss"]],
  ["😗", "kissing", "Kissing Face", ["kiss"]],
  ["😋", "yum", "Face Savoring Food", ["tasty", "delicious"]],
  ["😛", "stuck_out_tongue", "Face with Tongue", ["tongue", "silly"]],
  ["😜", "stuck_out_tongue_winking_eye", "Winking Face with Tongue", ["tongue", "silly"]],
  ["🤪", "zany_face", "Zany Face", ["crazy", "silly"]],
  ["🤔", "thinking", "Thinking Face", ["hmm", "think"]],
  ["🤨", "raised_eyebrow", "Face with Raised Eyebrow", ["skeptic", "doubt"]],
  ["😐", "neutral_face", "Neutral Face", ["meh"]],
  ["😴", "sleeping", "Sleeping Face", ["sleep", "tired", "zzz"]],
  ["😎", "sunglasses", "Smiling Face with Sunglasses", ["cool", "shades"]],
  ["🤓", "nerd_face", "Nerd Face", ["geek", "smart"]],
  ["😭", "sob", "Loudly Crying Face", ["cry", "sad", "tears"]],
  ["😡", "rage", "Pouting Face", ["angry", "mad"]],
  ["😢", "cry", "Crying Face", ["sad", "tears"]],
  ["😱", "scream", "Face Screaming in Fear", ["shock", "fear"]],
  ["🥳", "partying_face", "Partying Face", ["party", "celebrate"]],
  ["🥺", "pleading_face", "Pleading Face", ["beg", "puppy"]],
  ["😬", "grimacing", "Grimacing Face", ["awkward"]],
  ["🤯", "exploding_head", "Exploding Head", ["mind", "blown", "wow"]],
  ["😏", "smirk", "Smirking Face", ["smug"]],
  ["😴", "zzz", "Zzz", ["sleep", "tired"]],
]);

const PEOPLE = build("people", [
  ["👋", "wave", "Waving Hand", ["hello", "hi", "bye"], true],
  ["🤚", "raised_back_of_hand", "Raised Back of Hand", ["stop"], true],
  ["✋", "hand", "Raised Hand", ["stop", "high five"], true],
  ["👌", "ok_hand", "OK Hand", ["okay", "perfect"], true],
  ["🤏", "pinching_hand", "Pinching Hand", ["small", "tiny"], true],
  ["✌️", "v", "Victory Hand", ["peace", "victory"], true],
  ["🤞", "crossed_fingers", "Crossed Fingers", ["luck", "hope"], true],
  ["🤟", "love_you_gesture", "Love-You Gesture", ["ily", "love"], true],
  ["🤘", "metal", "Sign of the Horns", ["rock", "metal"], true],
  ["👍", "thumbsup", "Thumbs Up", ["like", "yes", "approve", "thumbs up"], true],
  ["👎", "thumbsdown", "Thumbs Down", ["dislike", "no", "thumbs down"], true],
  ["👊", "fist", "Oncoming Fist", ["punch", "bro"], true],
  ["✊", "raised_fist", "Raised Fist", ["power", "solidarity"], true],
  ["👏", "clap", "Clapping Hands", ["applause", "bravo"], true],
  ["🙌", "raised_hands", "Raising Hands", ["celebrate", "praise"], true],
  ["🙏", "pray", "Folded Hands", ["please", "thanks", "pray"], true],
  ["💪", "muscle", "Flexed Biceps", ["strong", "gym"], true],
  ["👀", "eyes", "Eyes", ["look", "watch"]],
  ["🧠", "brain", "Brain", ["smart", "think"]],
  ["👶", "baby", "Baby", ["child", "infant"], true],
  ["🧑", "person", "Person", ["adult"], true],
  ["👨", "man", "Man", ["male"], true],
  ["👩", "woman", "Woman", ["female"], true],
  ["👮", "police_officer", "Police Officer", ["cop", "law"], true],
  ["🕵️", "detective", "Detective", ["spy", "investigate"], true],
  ["👻", "ghost", "Ghost", ["boo", "spooky"]],
  ["🤖", "robot", "Robot", ["bot", "ai"]],
]);

const ANIMALS = build("animals", [
  ["🐶", "dog", "Dog Face", ["puppy", "pet"]],
  ["🐱", "cat", "Cat Face", ["kitten", "pet"]],
  ["🐭", "mouse", "Mouse Face", ["rodent"]],
  ["🐹", "hamster", "Hamster", ["pet"]],
  ["🐰", "rabbit", "Rabbit Face", ["bunny"]],
  ["🦊", "fox", "Fox", ["sly"]],
  ["🐻", "bear", "Bear", ["teddy"]],
  ["🐼", "panda", "Panda", ["bear"]],
  ["🐨", "koala", "Koala", ["bear"]],
  ["🐯", "tiger", "Tiger Face", ["cat", "wild"]],
  ["🦁", "lion", "Lion", ["king", "wild"]],
  ["🐮", "cow", "Cow Face", ["moo"]],
  ["🐷", "pig", "Pig Face", ["oink"]],
  ["🐸", "frog", "Frog", ["toad"]],
  ["🐵", "monkey_face", "Monkey Face", ["ape"]],
  ["🐔", "chicken", "Chicken", ["bird", "hen"]],
  ["🐧", "penguin", "Penguin", ["bird"]],
  ["🦄", "unicorn", "Unicorn", ["magic", "horse"]],
  ["🐝", "bee", "Honeybee", ["buzz", "insect"]],
  ["🦋", "butterfly", "Butterfly", ["insect"]],
  ["🐢", "turtle", "Turtle", ["slow"]],
  ["🐙", "octopus", "Octopus", ["sea"]],
  ["🐠", "tropical_fish", "Tropical Fish", ["sea"]],
  ["🐬", "dolphin", "Dolphin", ["sea"]],
  ["🐳", "whale", "Spouting Whale", ["sea"]],
  ["🌵", "cactus", "Cactus", ["plant", "desert"]],
  ["🌲", "evergreen_tree", "Evergreen Tree", ["plant", "forest"]],
  ["🌸", "cherry_blossom", "Cherry Blossom", ["flower", "spring"]],
  ["🌹", "rose", "Rose", ["flower", "love"]],
  ["🌻", "sunflower", "Sunflower", ["flower"]],
  ["🍀", "four_leaf_clover", "Four Leaf Clover", ["luck"]],
  ["🌍", "earth_africa", "Globe Showing Europe-Africa", ["world", "earth"]],
]);

const FOOD = build("food", [
  ["🍏", "green_apple", "Green Apple", ["fruit"]],
  ["🍎", "apple", "Red Apple", ["fruit"]],
  ["🍌", "banana", "Banana", ["fruit"]],
  ["🍉", "watermelon", "Watermelon", ["fruit"]],
  ["🍇", "grapes", "Grapes", ["fruit"]],
  ["🍓", "strawberry", "Strawberry", ["fruit"]],
  ["🍒", "cherries", "Cherries", ["fruit"]],
  ["🍑", "peach", "Peach", ["fruit"]],
  ["🍍", "pineapple", "Pineapple", ["fruit"]],
  ["🥑", "avocado", "Avocado", ["fruit", "veggie"]],
  ["🍅", "tomato", "Tomato", ["veggie"]],
  ["🌽", "corn", "Ear of Corn", ["veggie"]],
  ["🥕", "carrot", "Carrot", ["veggie"]],
  ["🍞", "bread", "Bread", ["loaf"]],
  ["🧀", "cheese", "Cheese Wedge", ["dairy"]],
  ["🍔", "hamburger", "Hamburger", ["burger", "fast food"]],
  ["🍟", "fries", "French Fries", ["fast food"]],
  ["🍕", "pizza", "Pizza", ["slice", "italian"]],
  ["🌭", "hotdog", "Hot Dog", ["sausage"]],
  ["🌮", "taco", "Taco", ["mexican"]],
  ["🍜", "ramen", "Steaming Bowl", ["noodles"]],
  ["🍣", "sushi", "Sushi", ["japanese"]],
  ["🍦", "icecream", "Soft Ice Cream", ["dessert"]],
  ["🍩", "doughnut", "Doughnut", ["dessert"]],
  ["🍪", "cookie", "Cookie", ["dessert"]],
  ["🎂", "birthday", "Birthday Cake", ["cake", "party"]],
  ["🍰", "cake", "Shortcake", ["dessert"]],
  ["🍫", "chocolate_bar", "Chocolate Bar", ["sweet"]],
  ["🍿", "popcorn", "Popcorn", ["movie", "snack"]],
  ["☕", "coffee", "Hot Beverage", ["coffee", "tea"]],
  ["🍵", "tea", "Teacup Without Handle", ["drink"]],
  ["🍺", "beer", "Beer Mug", ["drink", "alcohol"]],
  ["🍷", "wine_glass", "Wine Glass", ["drink", "alcohol"]],
  ["🥂", "champagne", "Clinking Glasses", ["cheers", "celebrate"]],
]);

const TRAVEL = build("travel", [
  ["🚗", "car", "Automobile", ["vehicle", "drive"]],
  ["🚕", "taxi", "Taxi", ["cab"]],
  ["🚌", "bus", "Bus", ["transit"]],
  ["🚑", "ambulance", "Ambulance", ["emergency"]],
  ["🚓", "police_car", "Police Car", ["cop"]],
  ["🚲", "bike", "Bicycle", ["cycle"]],
  ["🏍️", "motorcycle", "Motorcycle", ["bike"]],
  ["✈️", "airplane", "Airplane", ["flight", "fly", "travel"]],
  ["🚀", "rocket", "Rocket", ["space", "launch"]],
  ["🚁", "helicopter", "Helicopter", ["fly"]],
  ["⛵", "sailboat", "Sailboat", ["boat", "sea"]],
  ["🚢", "ship", "Ship", ["boat", "cruise"]],
  ["🚂", "train", "Locomotive", ["rail"]],
  ["🚦", "vertical_traffic_light", "Vertical Traffic Light", ["signal"]],
  ["🗺️", "world_map", "World Map", ["travel", "geography"]],
  ["🗽", "statue_of_liberty", "Statue of Liberty", ["new york", "usa"]],
  ["🗼", "tokyo_tower", "Tokyo Tower", ["japan"]],
  ["🏰", "european_castle", "Castle", ["fortress"]],
  ["🏖️", "beach_umbrella", "Beach with Umbrella", ["vacation", "sea"]],
  ["🏔️", "mountain_snow", "Snow-Capped Mountain", ["peak"]],
  ["🌋", "volcano", "Volcano", ["eruption"]],
  ["🏕️", "camping", "Camping", ["tent", "outdoors"]],
  ["🌃", "night_with_stars", "Night with Stars", ["city", "evening"]],
  ["🌉", "bridge_at_night", "Bridge at Night", ["city"]],
  ["🏠", "house", "House", ["home"]],
  ["🏢", "office", "Office Building", ["work"]],
  ["⛰️", "mountain", "Mountain", ["hill"]],
  ["🏝️", "desert_island", "Desert Island", ["vacation"]],
]);

const ACTIVITIES = build("activities", [
  ["⚽", "soccer", "Soccer Ball", ["football", "sport"]],
  ["🏀", "basketball", "Basketball", ["sport", "hoops"]],
  ["🏈", "football", "American Football", ["sport"]],
  ["⚾", "baseball", "Baseball", ["sport"]],
  ["🎾", "tennis", "Tennis", ["sport", "racket"]],
  ["🏐", "volleyball", "Volleyball", ["sport"]],
  ["🏓", "ping_pong", "Ping Pong", ["table tennis"]],
  ["🏸", "badminton", "Badminton", ["sport"]],
  ["🥅", "goal_net", "Goal Net", ["sport"]],
  ["⛳", "golf", "Flag in Hole", ["sport"]],
  ["🎿", "ski", "Skis", ["snow", "winter"]],
  ["🏂", "snowboarder", "Snowboarder", ["snow", "winter"], true],
  ["🏆", "trophy", "Trophy", ["win", "award", "champion"]],
  ["🥇", "first_place", "1st Place Medal", ["gold", "win"]],
  ["🎯", "dart", "Bullseye", ["target", "aim"]],
  ["🎮", "video_game", "Video Game", ["gaming", "controller"]],
  ["🕹️", "joystick", "Joystick", ["gaming", "arcade"]],
  ["🎲", "game_die", "Game Die", ["dice", "luck"]],
  ["🎸", "guitar", "Guitar", ["music", "rock"]],
  ["🎹", "musical_keyboard", "Musical Keyboard", ["piano", "music"]],
  ["🎺", "trumpet", "Trumpet", ["music", "jazz"]],
  ["🎻", "violin", "Violin", ["music"]],
  ["🥁", "drum", "Drum", ["music", "beat"]],
  ["🎤", "microphone", "Microphone", ["sing", "karaoke"]],
  ["🎨", "art", "Artist Palette", ["paint", "creative"]],
  ["🎬", "clapper", "Clapper Board", ["movie", "film"]],
  ["🎭", "performing_arts", "Performing Arts", ["theater", "drama"]],
  ["🎉", "tada", "Party Popper", ["party", "celebrate", "congrats"]],
  ["🎊", "confetti_ball", "Confetti Ball", ["party", "celebrate"]],
  ["🎈", "balloon", "Balloon", ["party"]],
  ["🎁", "gift", "Wrapped Gift", ["present", "birthday"]],
]);

const OBJECTS = build("objects", [
  ["💡", "bulb", "Light Bulb", ["idea", "light"]],
  ["🔦", "flashlight", "Flashlight", ["torch", "light"]],
  ["🕯️", "candle", "Candle", ["light", "flame"]],
  ["📱", "iphone", "Mobile Phone", ["phone", "cell"]],
  ["💻", "computer", "Laptop", ["pc", "work"]],
  ["⌨️", "keyboard", "Keyboard", ["type"]],
  ["🖥️", "desktop_computer", "Desktop Computer", ["pc"]],
  ["🖨️", "printer", "Printer", ["office"]],
  ["📷", "camera", "Camera", ["photo"]],
  ["🎥", "movie_camera", "Movie Camera", ["film", "video"]],
  ["📺", "tv", "Television", ["screen"]],
  ["📻", "radio", "Radio", ["music"]],
  ["⏰", "alarm_clock", "Alarm Clock", ["time", "wake"]],
  ["⌚", "watch", "Watch", ["time"]],
  ["🔋", "battery", "Battery", ["power", "charge"]],
  ["🔌", "electric_plug", "Electric Plug", ["power"]],
  ["💰", "moneybag", "Money Bag", ["cash", "rich"]],
  ["💵", "dollar", "Dollar Banknote", ["money", "cash"]],
  ["💳", "credit_card", "Credit Card", ["pay", "money"]],
  ["💎", "gem", "Gem Stone", ["diamond", "jewel"]],
  ["🔑", "key", "Key", ["lock", "unlock"]],
  ["🔒", "lock", "Locked", ["secure", "private"]],
  ["🔓", "unlock", "Unlocked", ["open"]],
  ["🔨", "hammer", "Hammer", ["tool", "build"]],
  ["🔧", "wrench", "Wrench", ["tool", "fix"]],
  ["⚙️", "gear", "Gear", ["settings", "cog"]],
  ["📚", "books", "Books", ["read", "library"]],
  ["📖", "book", "Open Book", ["read"]],
  ["✏️", "pencil", "Pencil", ["write", "edit"]],
  ["📌", "pushpin", "Pushpin", ["pin", "note"]],
  ["📎", "paperclip", "Paperclip", ["attach"]],
  ["✂️", "scissors", "Scissors", ["cut"]],
  ["🔍", "mag", "Magnifying Glass", ["search", "find"]],
  ["💊", "pill", "Pill", ["medicine", "drug"]],
  ["🎓", "mortar_board", "Graduation Cap", ["school", "graduate"]],
]);

const SYMBOLS = build("symbols", [
  ["❤️", "heart", "Red Heart", ["love", "like"]],
  ["🧡", "orange_heart", "Orange Heart", ["love"]],
  ["💛", "yellow_heart", "Yellow Heart", ["love"]],
  ["💚", "green_heart", "Green Heart", ["love"]],
  ["💙", "blue_heart", "Blue Heart", ["love"]],
  ["💜", "purple_heart", "Purple Heart", ["love"]],
  ["🖤", "black_heart", "Black Heart", ["love", "dark"]],
  ["🤍", "white_heart", "White Heart", ["love"]],
  ["💔", "broken_heart", "Broken Heart", ["sad", "breakup"]],
  ["💕", "two_hearts", "Two Hearts", ["love"]],
  ["💖", "sparkling_heart", "Sparkling Heart", ["love"]],
  ["💯", "100", "Hundred Points", ["perfect", "score"]],
  ["🔥", "fire", "Fire", ["lit", "hot", "flame"]],
  ["⭐", "star", "Star", ["favorite"]],
  ["🌟", "star2", "Glowing Star", ["shine", "sparkle"]],
  ["✨", "sparkles", "Sparkles", ["shine", "magic"]],
  ["⚡", "zap", "High Voltage", ["lightning", "power"]],
  ["💥", "boom", "Collision", ["explosion", "bang"]],
  ["✅", "white_check_mark", "Check Mark Button", ["done", "yes", "ok"]],
  ["❌", "x", "Cross Mark", ["no", "wrong"]],
  ["❓", "question", "Question Mark", ["help", "ask"]],
  ["❗", "exclamation", "Exclamation Mark", ["alert"]],
  ["⚠️", "warning", "Warning", ["caution", "alert"]],
  ["♻️", "recycle", "Recycling Symbol", ["green", "eco"]],
  ["🔔", "bell", "Bell", ["notify", "alert"]],
  ["🔕", "no_bell", "Bell with Slash", ["mute", "silent"]],
  ["➕", "heavy_plus_sign", "Plus", ["add"]],
  ["➖", "heavy_minus_sign", "Minus", ["subtract"]],
  ["🔴", "red_circle", "Red Circle", ["dot"]],
  ["🟢", "green_circle", "Green Circle", ["dot", "ok"]],
  ["🔵", "blue_circle", "Blue Circle", ["dot"]],
  ["🆗", "ok", "OK Button", ["okay"]],
  ["🆕", "new", "New Button", ["fresh"]],
  ["©️", "copyright", "Copyright", ["legal"]],
]);

const FLAGS = build("flags", [
  ["🏁", "checkered_flag", "Chequered Flag", ["race", "finish"]],
  ["🚩", "triangular_flag_on_post", "Triangular Flag", ["mark", "warning"]],
  ["🏳️", "white_flag", "White Flag", ["surrender"]],
  ["🏴", "black_flag", "Black Flag", ["pirate"]],
  ["🏳️‍🌈", "rainbow_flag", "Rainbow Flag", ["pride", "lgbt"]],
  ["🇺🇸", "us", "Flag United States", ["usa", "america"]],
  ["🇬🇧", "gb", "Flag United Kingdom", ["uk", "britain"]],
  ["🇨🇦", "ca", "Flag Canada", ["canada"]],
  ["🇫🇷", "fr", "Flag France", ["france"]],
  ["🇩🇪", "de", "Flag Germany", ["germany"]],
  ["🇮🇹", "it", "Flag Italy", ["italy"]],
  ["🇪🇸", "es", "Flag Spain", ["spain"]],
  ["🇯🇵", "jp", "Flag Japan", ["japan"]],
  ["🇰🇷", "kr", "Flag South Korea", ["korea"]],
  ["🇨🇳", "cn", "Flag China", ["china"]],
  ["🇮🇳", "in", "Flag India", ["india"]],
  ["🇧🇷", "br", "Flag Brazil", ["brazil"]],
  ["🇲🇽", "mx", "Flag Mexico", ["mexico"]],
  ["🇦🇺", "au", "Flag Australia", ["australia"]],
  ["🇳🇱", "nl", "Flag Netherlands", ["netherlands"]],
  ["🇸🇪", "se", "Flag Sweden", ["sweden"]],
  ["🇷🇺", "ru", "Flag Russia", ["russia"]],
  ["🇿🇦", "za", "Flag South Africa", ["south africa"]],
]);

export const EMOJI_DATA: EmojiEntry[] = [
  ...SMILEYS,
  ...PEOPLE,
  ...ANIMALS,
  ...FOOD,
  ...TRAVEL,
  ...ACTIVITIES,
  ...OBJECTS,
  ...SYMBOLS,
  ...FLAGS,
];

// Shortcode lookup map (generated at module load). First occurrence wins.
export const SHORTCODE_MAP: Map<string, string> = (() => {
  const m = new Map<string, string>();
  for (const e of EMOJI_DATA) {
    if (!m.has(e.shortcode)) m.set(e.shortcode, e.emoji);
  }
  return m;
})();

/** Emojis grouped by category, preserving dataset order. */
export const EMOJI_BY_CATEGORY: Record<EmojiCategory, EmojiEntry[]> = EMOJI_CATEGORIES.reduce(
  (acc, c) => {
    acc[c.id] = EMOJI_DATA.filter((e) => e.category === c.id);
    return acc;
  },
  {} as Record<EmojiCategory, EmojiEntry[]>,
);

/** Live, case-insensitive search across name, shortcode and keywords. */
export function searchEmojis(query: string): EmojiEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return EMOJI_DATA.filter((e) => {
    if (e.shortcode.includes(q) || e.name.toLowerCase().includes(q)) return true;
    return e.keywords.some((k) => k.toLowerCase().includes(q));
  });
}
