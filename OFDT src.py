"""SNIPERR checker - single-source build.

The checker engine and desktop UI backend are bundled in this one Python file.
"""
from __future__ import annotations

# Minimal dependency bootstrap. The engine can use optional curl_cffi/tls_client,
# but requests is enough as its standard fallback.
import importlib.util as _importlib_util
import subprocess as _bootstrap_subprocess
import sys as _bootstrap_sys

def _ensure_http_dependency() -> None:
    if any(_importlib_util.find_spec(name) is not None for name in ("curl_cffi", "tls_client", "requests")):
        return
    try:
        _bootstrap_subprocess.run(
            [_bootstrap_sys.executable, "-m", "pip", "install", "requests"],
            check=True,
            stdout=_bootstrap_subprocess.DEVNULL,
            stderr=_bootstrap_subprocess.DEVNULL,
        )
    except Exception as exc:
        raise SystemExit("Sniperr needs the Python 'requests' package and could not install it automatically.") from exc

_ensure_http_dependency()
del _ensure_http_dependency

import base64
import json
import math
import os
import queue
import random
import re
import sqlite3
import string
import threading
import time
import uuid
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import quote

try:
    from curl_cffi import requests as curl_requests
    from curl_cffi.requests import Session as CurlSession
    HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    CurlSession = None
    HAS_CURL_CFFI = False

try:
    import tls_client
    HAS_TLS_CLIENT = True
except ImportError:
    tls_client = None
    HAS_TLS_CLIENT = False

try:
    import requests as std_requests
except ImportError:
    std_requests = None

if not HAS_CURL_CFFI and not HAS_TLS_CLIENT and std_requests is None:
    raise SystemExit("Missing dependency.\nRun: py -m pip install curl_cffi requests")

APP_TITLE = "discord.gg/sniperr"
DISCORD_PATH = "/api/v9/unique-username/username-attempt-unauthed"
DISCORD_HOSTS = ["https://discord.com", "https://canary.discord.com", "https://ptb.discord.com"]

SETTINGS_FILE = "Ogsniper-rapid-settings.json"
PROXY_FILE = "proxies.txt"
RESULTS_FILE = "available.txt"
HISTORY_FILE = "Ogsniper-history.sqlite3"
WORDS_FILE = "words.txt"

MIN_CPS = 1.0
MAX_CPS = 5000.0
DEFAULT_CPS = 200.0
DEFAULT_TIMEOUT_MS = 2500

CIRCUIT_BREAK_THRESHOLD = 3
CIRCUIT_BREAK_SEC = 6.0
ROUTE_COOLDOWN = 0.15
MAX_PER_ROUTE = 12
SESSION_MAX_REQUESTS = 50
PROXY_DEAD_STRIKES = 3
PROXY_DEAD_COOLDOWN = 60.0
UNKNOWN_RETRY_ATTEMPTS = 3

RATELIMIT_SAFETY_PCT = 0.90
BUCKET_TRACK_MAX = 512

MIN_WORKERS = 64
MAX_WORKERS = 500
WORKER_CPS_FACTOR = 3.0
READY_DELAY_SEC = 5

ALNUM = string.ascii_lowercase + string.digits
LETTERS = string.ascii_lowercase
DIGITS = string.digits


# ═════════════════════════════════════════════════════════════════════════════
# CLIENT FINGERPRINT (internal — never shown)
# ═════════════════════════════════════════════════════════════════════════════

def _gen_installation_id() -> str:
    return str(uuid.uuid4())

def _gen_launch_signature() -> str:
    return base64.b64encode(os.urandom(16)).decode().rstrip("=")

def _build_super_properties(host: str) -> str:
    if "canary" in host: channel = "canary"
    elif "ptb" in host: channel = "ptb"
    else: channel = "stable"

    props = {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": channel,
        "client_version": "1.0.9166",
        "os_version": "10.0.22631",
        "os_arch": "x64",
        "system_locale": "en-US",
        "client_build_number": random.randint(270000, 275000),
        "native_build_number": random.randint(43000, 45000),
        "client_event_source": None,
        "launch_signature": _gen_launch_signature(),
        "installation_id": _gen_installation_id(),
    }
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def _build_x_fingerprint() -> str:
    fp = {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": "1.0.9166",
        "os_version": "10.0.22631",
        "os_arch": "x64",
        "system_locale": "en-US",
        "client_build_number": random.randint(270000, 275000),
        "native_build_number": random.randint(43000, 45000),
    }
    raw = json.dumps(fp, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def _build_headers(host: str) -> dict:
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://discord.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://discord.com/channels/@me",
        "sec-ch-ua": '"Google Chrome";v="120", "Chromium";v="120", "Not(A:Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": _build_super_properties(host),
        "x-fingerprint": _build_x_fingerprint(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# WORD POOLS
# ═════════════════════════════════════════════════════════════════════════════

SHORT_WORD_BLOB = (
    "acidaeroagedallyapexarchariaatomauraaxisbanebeambetabiteblipblurboltbrimbyte"
    "calmcavecharclawcodecoldcorecosycrowdawndazedeckdripduskechoedgeepicfangfern"
    "fluxfoamgaleglowgridgrimhalohazehushirisjadejoltkilokitelarklavalimelinkluna"
    "lynxmacemintmistmusemythnavyneonnovaonyxopalpalepeakplumrainriftsagesilksnow"
    "solostarstemtidevoidwavewispwolfxenoyarnyetizealzerozinczonearilbuhrcymafane"
    "ilexixiajapekelpkithlinnrimewoadyarefardfoudhylekamemiltuveafirn"
)
SHORT_WORDS = [SHORT_WORD_BLOB[i:i+4] for i in range(0, len(SHORT_WORD_BLOB), 4)]

RARE_WORD_BLOB = (
    "amberazureemberfablefrostorbitpixelpulsequillslatesparkabysmadretaegisaglet"
    "alateamiceanileapianarborardorargotaskewattarauricazothbardobezelbightbohea"
    "boricbrumecairncalyxchertchirkcivetcladeclarycoigndightdongadrossducaleagree"
    "clateduceelideenvoiergotetweefetorfirthflumefrondgamicgaultghyllglebeglume"
    "goralgrithguyothalerhelvehilumhouriicticinurnjabotjorumkedgeknurllaitylathyl"
    "emanlumenmaclemaundmerlemurexnacrenivalnonceockerogiveorlopoxterpavidpewit"
    "pingoplicaprillquernquoinratalroblesakersalepscurfsepalshawmsilexsizarskirl"
    "soughstoupswaletargetigontopertronaulemaumbelurialvaticvelarvireowhealwight"
    "xeniczayinzebeczonda"
)
RARE_WORDS = [RARE_WORD_BLOB[i:i+5] for i in range(0, len(RARE_WORD_BLOB), 5)]

OBSCURE_WORD_BLOB = (
    "abditablowaboonabsitacmicaduncaegiraiveralbeealephalgidalureambitamoleanelean"
    "entannalanomyarameargalarlesaroidasconascusaulicavensavisoaxileazidebairnbalky"
    "bardebaricbassibattubawtybeanobedelbeedibemixbermebirleblateblawnblentblore"
    "boartbocceboffobolarbonceboralbortyboskybractbramebromebunducadgecairdcalky"
    "camuscavieceorlceredchapechirmchirtchylecimarclepeclourcoblecogoncoombcozen"
    "crakecreelcronkcruseculchculetcusecdavitdeavedeedydemitdizendobladoorndoura"
    "dowiedrantdreckdunamealedephoretapeettlefanalfaughfeuarflaryfleamfliskflong"
    "flotaforbyfrapefrithfuglegallyganevgawkygibusgimelgiponglairgleetgliskgopak"
    "gricegromagrykegurshhainthamalhaughhaverhelothormehoughinklejagerjambujiber"
    "juralkabobkaiakkalamkepiskirbykvasslairdlanailarumlaverleachlearylimenlorel"
    "lurrymaficmalicmargemashymesicmoraemowramucidmungonairunaresnievenogalnooky"
    "oaredoctadodyleollavopineorpinottarpangapannepareupavispeerypeisepiculpisky"
    "pleonpraamproemquirtrabatraneerenterhemerhyneriantronderubleruchesabalsagum"
    "samelscaupsegarselahsengiseracshielsmazesnecksnoodsorelspeansteddstirksward"
    "tabortawietentythirltichytorsktrullulnarunlayvarecvenalvinalvolarwackewaled"
    "wealdwiddywirrawurstxylanyamenyapokyestyzabrazibetzillszoril"
)
OBSCURE_WORDS = [OBSCURE_WORD_BLOB[i:i+5] for i in range(0, len(OBSCURE_WORD_BLOB), 5)]
ALL_WORDS = list(dict.fromkeys(SHORT_WORDS + RARE_WORDS + OBSCURE_WORDS))

POOL_A = (
    "north south east west upper lower inner outer red blue black white green gold "
    "silver pink purple orange gray grey brown cyan teal navy lime mint coral ruby "
    "jade pearl ivory onyx amber cherry copper bronze indigo violet dawn dusk morning "
    "evening night day noon midnight sunrise sunset twilight summer winter spring autumn "
    "wild calm cool warm cold hot fresh old new young sharp smooth rough soft hard "
    "quick slow fast bright dark dull clear foggy cloudy sunny stormy quiet loud silent "
    "roaring sky sea ocean coast river lake forest wood tree leaf stone rock sand snow "
    "rain wind storm cloud sun moon star fire water ice earth mountain hill valley canyon "
    "desert cliff cave spring tide wave thunder lightning breeze mist frost hail drizzle "
    "flood drought blizzard tornado hurricane monsoon cyclone peace joy love hope dream "
    "fear brave kind pride rage fury soul spirit ghost mercy grace honor glory faith trust "
    "truth memory secret whisper promise fate destiny karma fall rise run walk jump fly "
    "swim dive climb break crack burn glow shine spark hit kick punch slash cut chop slice "
    "dash sprint chase hunt seek find keep lose sword shield crown ring gem coin book key "
    "lock door gate wall tower bridge road path trail camp tent hut house home castle "
    "throne spear bow arrow axe hammer dagger blade helm armor cloak robe mask glove boot "
    "belt wolf fox bear lion tiger eagle hawk crow raven owl snake shark whale deer elk "
    "moose hare rabbit mouse cat dog lynx panther leopard jaguar puma boar stag"
).split()

POOL_B = (
    "town city village hamlet fort keep manor hall temple shrine church market port "
    "harbor dock bay cove inlet isle head hand foot arm leg eye ear nose mouth tooth "
    "claw fang wing tail horn steel iron brass copper glass cloth silk wool leather "
    "paper clay one two three four five six seven eight nine ten comet meteor planet "
    "orbit galaxy nebula cosmos ether void abyss zenith horizon aurora eclipse solstice "
    "rifle pistol cannon mortar mine bomb grenade missile rocket sniper scope trigger "
    "bullet shell song tune beat rhythm chord melody anthem hymn chorus verse pixel "
    "byte code chip data cyber crypto laser radar signal circuit matrix nexus vector "
    "blaze ash smoke dust mud thorn ivy moss fern reed vine root bark branch seed "
    "flower petal bloom berry fruit apple grape lemon peach plum pear bite drink eat "
    "sleep wake sing dance play laugh cry shout yell scream talk speak listen hear see "
    "look watch search explore wander happy sad angry tired hungry thirsty sleepy awake "
    "alive dead real fake true false good bad evil holy clean dirty rich poor wise"
).split()

POOL_C = (
    "shadow phantom specter wraith banshee revenant sorrow bliss chaos infinite "
    "infinity eternity forever always never mystic magical sacred holy divine cursed "
    "blessed gaming gamer player gamemaster gameover epic legend legendary mythical "
    "mythic mythos alpha beta gamma delta omega sigma theta lambda victory triumph "
    "defeat glory shame puzzle riddle mystery enigma cipher wanderlust adventure "
    "quest voyage expedition harmony melody tempo tune silence echo murmur hum buzz "
    "phoenix dragon unicorn griffin pegasus sphinx cyberpunk neon chrome vapor synth "
    "retro future cosmic starlight moonlight twilight hunter tracker ranger scout "
    "explorer pioneer warrior fighter boxer wrestler samurai ninja shinobi sailor "
    "pirate captain admiral commander general knight paladin templar crusader guardian "
    "warden wizard mage sorcerer warlock enchanter conjurer bard minstrel troubadour "
    "poet artist painter monk priest cleric bishop cardinal pope king queen prince "
    "princess royal noble emperor empress smith mason weaver tanner tailor baker "
    "butcher doctor healer medic physician surgeon nurse teacher scholar student pupil "
    "master apprentice thief rogue bandit outlaw smuggler spy agent assassin marksman "
    "scout spirit soul essence being entity presence velocity momentum gravity inertia "
    "entropy cosmos void zenith abyss eternity infinity"
).split()

COMBO_WORDS = list(dict.fromkeys(POOL_A + POOL_B + POOL_C))
DICTIONARY_WORDS = list(dict.fromkeys((POOL_A + POOL_B + POOL_C)))
MEGA_WORDS = list(dict.fromkeys(COMBO_WORDS + ALL_WORDS + DICTIONARY_WORDS))

IMPERSONATE_PROFILES = ["chrome110", "chrome116", "chrome119", "chrome120"]

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
GREY = "\033[90m"
WHITE = "\033[97m"


def enable_ansi() -> None:
    if os.name == "nt":
        os.system("")
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(m)):
                k.SetConsoleMode(h, m.value | 0x0004)
            k.SetConsoleTitleW(APP_TITLE)
        except Exception:
            pass


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def banner() -> None:
    print(RED + "=" * 62)
    print("             discord.gg/sniperr")
    print("=" * 62 + RESET)


@dataclass
class Settings:
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    proxies: str = ""
    webhook: str = ""
    mode: str = "4c_smart"
    target_cps: float = DEFAULT_CPS
    show_taken: bool = True

    def sanitize(self):
        self.timeout_ms = max(900, min(8000, int(self.timeout_ms or DEFAULT_TIMEOUT_MS)))
        self.target_cps = max(MIN_CPS, min(MAX_CPS, float(self.target_cps or DEFAULT_CPS)))
        self.webhook = str(self.webhook or "").strip()
        self.proxies = str(self.proxies or "")
        if self.mode not in MODE_MAP:
            self.mode = "4c_smart"
        return self


def load_settings(base: Path) -> Settings:
    p = base / SETTINGS_FILE
    if not p.exists():
        return Settings()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return Settings(**{k: v for k, v in raw.items() if k in Settings.__dataclass_fields__}).sanitize()
    except Exception:
        return Settings()


def save_settings(base: Path, settings: Settings) -> None:
    (base / SETTINGS_FILE).write_text(json.dumps(asdict(settings.sanitize()), indent=2), encoding="utf-8")


class PersistentHistory:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.conn:
            self.conn.execute("CREATE TABLE IF NOT EXISTS seen (name TEXT PRIMARY KEY, ts REAL NOT NULL)")

    def claim(self, name: str) -> bool:
        with self.lock:
            try:
                with self.conn:
                    self.conn.execute("INSERT INTO seen(name, ts) VALUES (?, ?)", (name, time.time()))
                return True
            except sqlite3.IntegrityError:
                return False

    def count(self) -> int:
        with self.lock:
            row = self.conn.execute("SELECT COUNT(*) FROM seen").fetchone()
            return int(row[0]) if row else 0

    def close(self) -> None:
        with self.lock:
            self.conn.close()


def _decode_base(index: int, charset: str, length: int) -> str:
    base = len(charset)
    chars = [charset[0]] * length
    for pos in range(length - 1, -1, -1):
        index, rem = divmod(index, base)
        chars[pos] = charset[rem]
    return "".join(chars)


def _decode_semi(idx: int, seps: str, body_len: int, charset: str) -> str:
    per_sep = (body_len + 1) * (len(charset) ** body_len)
    sep_idx, rest = divmod(idx, per_sep)
    pos, body_idx = divmod(rest, len(charset) ** body_len)
    body = _decode_base(body_idx, charset, body_len)
    chars = list(body)
    chars.insert(pos, seps[sep_idx])
    return "".join(chars)


MODE_MAP = {
    # Semi 3C
    "1": ("semi_3c_both", "Semi 3C BOTH", "a_7x / .q2m"),
    "2": ("semi_3c_dot", "Semi 3C DOT", "a.7x / .q2m"),
    "3": ("semi_3c_under", "Semi 3C _", "a_7x / _q2m"),
    # Semi 3N
    "4": ("semi_3n_both", "Semi 3N BOTH", "1.23 / 4_56"),
    "5": ("semi_3n_dot", "Semi 3N DOT", "1.23 / 45.6"),
    "6": ("semi_3n_under", "Semi 3N _", "1_23 / 12_3"),
    # Semi 4N
    "7": ("semi_4n_both", "Semi 4N BOTH", "1.234 / 12_34"),
    "8": ("semi_4n_dot", "Semi 4N DOT", "1.234 / 12.34"),
    "9": ("semi_4n_under", "Semi 4N _", "1_234 / 12_34"),
    # Straight character modes
    "10": ("2c", "2C", "a7"),
    "11": ("3c_smart", "3C Smart", "v0m"),
    "12": ("4c_smart", "4C Smart", "q7m2"),
    "13": ("5c", "5C Smart", "q7m2x"),
    "14": ("3l", "3L", "abc"),
    "15": ("4l", "4L", "abcd"),
    "16": ("5l", "5L", "abcde"),
    "17": ("3n", "3N", "123"),
    "18": ("4n", "4N", "1234"),
    "19": ("5n", "5N", "12345"),
    # Word modes
    "20": ("word_short", "Short words", "acid / nova"),
    "21": ("word_rare", "Rare words", "amber / lumen"),
    "22": ("word_obscure", "Obscure words", "abdit / cronk"),
    "23": ("word_all", "All word pools", "all embedded"),
    "24": ("word_sep", "Word + . / _", "lumen_ / .lumen"),
    "25": ("word_join", "Word pairs", "eastcoast / firefly"),
    "26": ("word_dict", "Big dictionary", "dragon / phoenix"),
    "27": ("word_dict_join", "Dictionary pairs", "silentwolf / starborn"),
    "28": ("word_mega_join", "ALL words paired", "everything combined"),
    "M": ("word_num_word", "MIX: word+num+word", "fire7wolf / nova.42.sky"),
}
MODE_BY_ID = {v[0]: v for v in MODE_MAP.values()}


class NameGenerator:
    def __init__(self, mode: str, seed: Optional[int] = None):
        self.mode = mode
        self.rng = random.Random(seed if seed is not None else random.SystemRandom().getrandbits(64))
        self.counter = 0
        self.total = self._total()
        self.bits = max(1, (self.total - 1).bit_length())
        self.mask = (1 << self.bits) - 1
        self.rounds = []
        for _ in range(4):
            self.rounds.append((
                self.rng.randrange(1, self.mask + 1) | 1,
                self.rng.randrange(0, self.mask + 1),
                self.rng.randint(1, max(1, self.bits - 1)),
                self.rng.randint(1, max(1, self.bits - 1)),
            ))

    def _total(self) -> int:
        m = self.mode
        n = len(ALNUM)
        if m == "semi_3c_both": return 2 * 4 * (n ** 3)
        if m == "semi_3c_dot": return 4 * (n ** 3)
        if m == "semi_3c_under": return 4 * (n ** 3)
        if m == "semi_3n_both": return 2 * 4 * (10 ** 3)
        if m == "semi_3n_dot": return 4 * (10 ** 3)
        if m == "semi_3n_under": return 4 * (10 ** 3)
        if m == "semi_4n_both": return 2 * 5 * (10 ** 4)
        if m == "semi_4n_dot": return 5 * (10 ** 4)
        if m == "semi_4n_under": return 5 * (10 ** 4)
        if m == "2c": return n ** 2
        if m == "3c_smart": return n ** 3
        if m == "4c_smart": return n ** 4
        if m == "5c": return n ** 5
        if m == "3l": return len(LETTERS) ** 3
        if m == "4l": return len(LETTERS) ** 4
        if m == "5l": return len(LETTERS) ** 5
        if m == "3n": return len(DIGITS) ** 3
        if m == "4n": return len(DIGITS) ** 4
        if m == "5n": return len(DIGITS) ** 5
        if m == "word_short": return len(SHORT_WORDS)
        if m == "word_rare": return len(RARE_WORDS)
        if m == "word_obscure": return len(OBSCURE_WORDS)
        if m == "word_all": return len(ALL_WORDS)
        if m == "word_sep": return len(ALL_WORDS) * 4
        if m == "word_join":
            k = len(COMBO_WORDS); return k * (k - 1)
        if m == "word_dict": return len(DICTIONARY_WORDS)
        if m == "word_dict_join":
            k = len(DICTIONARY_WORDS); return k * (k - 1)
        if m == "word_mega_join":
            k = len(MEGA_WORDS); return k * (k - 1)
        if m == "word_num_word":
            k = len(MEGA_WORDS); return 4 * k * 10 * (k - 1)
        raise ValueError(f"unknown mode: {self.mode}")

    def _decode(self, idx: int) -> str:
        m = self.mode
        n = len(ALNUM)
        if m == "semi_3c_both": return _decode_semi(idx, "._", 3, ALNUM)
        if m == "semi_3c_dot":  return _decode_semi(idx, ".", 3, ALNUM)
        if m == "semi_3c_under":return _decode_semi(idx, "_", 3, ALNUM)
        if m == "semi_3n_both": return _decode_semi(idx, "._", 3, DIGITS)
        if m == "semi_3n_dot":  return _decode_semi(idx, ".", 3, DIGITS)
        if m == "semi_3n_under":return _decode_semi(idx, "_", 3, DIGITS)
        if m == "semi_4n_both": return _decode_semi(idx, "._", 4, DIGITS)
        if m == "semi_4n_dot":  return _decode_semi(idx, ".", 4, DIGITS)
        if m == "semi_4n_under":return _decode_semi(idx, "_", 4, DIGITS)
        if m == "2c": return _decode_base(idx, ALNUM, 2)
        if m == "3c_smart": return _decode_base(idx, ALNUM, 3)
        if m == "4c_smart": return _decode_base(idx, ALNUM, 4)
        if m == "5c": return _decode_base(idx, ALNUM, 5)
        if m == "3l": return _decode_base(idx, LETTERS, 3)
        if m == "4l": return _decode_base(idx, LETTERS, 4)
        if m == "5l": return _decode_base(idx, LETTERS, 5)
        if m == "3n": return _decode_base(idx, DIGITS, 3)
        if m == "4n": return _decode_base(idx, DIGITS, 4)
        if m == "5n": return _decode_base(idx, DIGITS, 5)
        if m == "word_short": return SHORT_WORDS[idx]
        if m == "word_rare": return RARE_WORDS[idx]
        if m == "word_obscure": return OBSCURE_WORDS[idx]
        if m == "word_all": return ALL_WORDS[idx]
        if m == "word_sep":
            wi, f = divmod(idx, 4); w = ALL_WORDS[wi]
            return (w + ".", w + "_", "." + w, "_" + w)[f]
        if m == "word_join":
            k = len(COMBO_WORDS); a, b = divmod(idx, k - 1)
            if b >= a: b += 1
            return COMBO_WORDS[a] + COMBO_WORDS[b]
        if m == "word_dict": return DICTIONARY_WORDS[idx]
        if m == "word_dict_join":
            k = len(DICTIONARY_WORDS); a, b = divmod(idx, k - 1)
            if b >= a: b += 1
            return DICTIONARY_WORDS[a] + DICTIONARY_WORDS[b]
        if m == "word_mega_join":
            k = len(MEGA_WORDS); a, b = divmod(idx, k - 1)
            if b >= a: b += 1
            return MEGA_WORDS[a] + MEGA_WORDS[b]
        if m == "word_num_word":
            k = len(MEGA_WORDS)
            sep_id = idx % 4; idx //= 4
            digit = idx % 10; idx //= 10
            w2 = idx % k; idx //= k
            w1 = idx % k
            if w2 == w1: w2 = (w2 + 1) % k
            a = MEGA_WORDS[w1]; b = MEGA_WORDS[w2]
            if sep_id == 0: return f"{a}{digit}{b}"
            if sep_id == 1: return f"{a}_{digit}_{b}"
            if sep_id == 2: return f"{a}.{digit}.{b}"
            return f"{a}{digit}.{b}"
        raise ValueError(m)

    def _permute_index(self, value: int) -> int:
        if self.total <= 1: return 0
        x = value & self.mask
        while True:
            for mult, add, sa, sb in self.rounds:
                x = (x + add) & self.mask
                x ^= x >> sa
                x = (x * mult) & self.mask
                x ^= x >> sb
                x &= self.mask
            if x < self.total:
                return x

    def next(self) -> str:
        idx = self._permute_index(self.counter)
        self.counter = (self.counter + 1) % self.total
        return self._decode(idx)


def normalize_proxy(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"): return None
    if raw.startswith(("http://", "https://", "socks5://", "socks5h://")):
        return raw.rstrip("/")
    if "@" in raw:
        auth, address = raw.rsplit("@", 1)
        if ":" in auth and ":" in address:
            user, password = auth.split(":", 1)
            host, port = address.rsplit(":", 1)
            if user and host and port.isdigit():
                return f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
    parts = raw.split(":")
    if len(parts) == 2:
        host, port = parts
        if host and port.isdigit():
            return f"http://{host}:{port}"
    if len(parts) >= 4:
        host, port, user = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        if host and port.isdigit() and user:
            return f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
    return None


def load_proxies(base: Path, settings: Settings) -> list:
    rows = []
    configured = settings.proxies.strip()
    if configured:
        rows.extend(re.split(r"[\r\n,]+", settings.proxies))
    else:
        p = base / PROXY_FILE
        if p.exists():
            try:
                rows.extend(p.read_text(encoding="utf-8", errors="ignore").splitlines())
            except OSError:
                pass
    out, seen = [], set()
    for row in rows:
        proxy = normalize_proxy(row)
        if proxy and proxy not in seen:
            out.append(proxy)
            seen.add(proxy)
    return out


@dataclass
class CheckResult:
    state: str
    status: int = 0
    retry_after: float = 0.0
    detail: str = ""
    latency_ms: float = 0.0


def format_stats(checked: int, taken: int, available: int, limited: int = 0) -> str:
    return (f"Checked {checked:,} | Taken {taken:,} | Available {available:,} "
            f"| Limited {limited:,}")


def worker_count_for(target_cps: float, proxy_count: int = 0) -> int:
    if proxy_count <= 0:
        return max(4, min(16, math.ceil(min(target_cps, 10.0) * 1.5)))
    return max(MIN_WORKERS, min(MAX_WORKERS, math.ceil(float(target_cps) * WORKER_CPS_FACTOR)))


# ═════════════════════════════════════════════════════════════════════════════
# WEBHOOK
# ═════════════════════════════════════════════════════════════════════════════

def _build_webhook_payload(username: str, mode_label: str) -> dict:
    return {
        "content": f"**AVAILABLE** `{username}`  ·  mode: {mode_label or 'unknown'}",
        "username": "Sniper",
    }


def _mask_url(url: str) -> str:
    url = url.strip()
    m = re.match(r"^(https://[^\s/]+/api/webhooks/\d+)/([^\s/?#]+)", url)
    if m:
        token = m.group(2)
        if len(token) > 10:
            return f"{m.group(1)}/{token[:4]}...{token[-4:]}"
        return f"{m.group(1)}/{token}"
    return url[:60] + ("..." if len(url) > 60 else "")


def _try_send_webhook(url: str, username: str, mode_label: str, timeout: int = 10) -> tuple:
    payload = _build_webhook_payload(username, mode_label)
    body_text = json.dumps(payload)
    errors = []

    if std_requests is not None:
        try:
            s = std_requests.Session()
            s.trust_env = False
            r = s.post(url, data=body_text,
                       headers={"Content-Type": "application/json"}, timeout=timeout)
            try: s.close()
            except Exception: pass
            if 200 <= r.status_code < 300:
                return True, "requests", ""
            errors.append(f"requests HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"requests {type(e).__name__}: {str(e)[:120]}")

    try:
        import urllib.request as urlreq
        import urllib.error as urlerr
        req = urlreq.Request(url, data=body_text.encode("utf-8"),
                             headers={"Content-Type": "application/json", "User-Agent": "sniperr/1.0"},
                             method="POST")
        opener = urlreq.build_opener(urlreq.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                if 200 <= resp.status < 300:
                    return True, "urllib", ""
        except urlerr.HTTPError as he:
            errors.append(f"urllib HTTP {he.code}")
    except Exception as e:
        errors.append(f"urllib {type(e).__name__}: {str(e)[:120]}")

    return False, "none", " | ".join(errors)


class WebhookSender:
    RATE_LIMIT_PER_MIN = 25
    MAX_ATTEMPTS = 3

    def __init__(self, url: str):
        self.url = url.strip()
        self._queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._request_times = deque()
        self._lock = threading.Lock()
        self._sent = 0
        self._failed = 0

    def start(self) -> bool:
        if self._thread is not None: return True
        self._thread = threading.Thread(target=self._run, daemon=True, name="webhook")
        self._thread.start()
        print(f"{GREY}[WEBHOOK] armed → {_mask_url(self.url)}{RESET}")
        return True

    def enqueue(self, username: str, mode_label: str) -> None:
        if not self.url: return
        self._queue.put_nowait((username, mode_label))

    def _wait_for_slot(self) -> None:
        while True:
            with self._lock:
                now = time.time()
                while self._request_times and self._request_times[0] < now - 60:
                    self._request_times.popleft()
                if len(self._request_times) < self.RATE_LIMIT_PER_MIN:
                    self._request_times.append(now); return
                wait = (self._request_times[0] + 60) - now
            if wait > 0:
                time.sleep(min(wait + 0.05, 5.0))

    def _run(self) -> None:
        try:
            while not self._stop.is_set() or not self._queue.empty():
                try:
                    username, mode_label = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                self._wait_for_slot()
                success = False
                for attempt in range(self.MAX_ATTEMPTS):
                    success, _b, _e = _try_send_webhook(self.url, username, mode_label)
                    if success: break
                    time.sleep(0.7 * (attempt + 1))
                with self._lock:
                    if success: self._sent += 1
                    else: self._failed += 1
        except Exception:
            pass

    def stop(self, drain_timeout: float = 15.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=drain_timeout)
        with self._lock:
            sent = self._sent; failed = self._failed
        if sent or failed:
            print(f"{GREY}[WEBHOOK] {sent} sent · {failed} failed{RESET}")


# ═════════════════════════════════════════════════════════════════════════════
# CHECKER
# ═════════════════════════════════════════════════════════════════════════════

CF_MARKERS = ("cf-chl", "cf_chl", "challenge-platform", "cf-please-wait",
              "<!doctype html", "<html", "just a moment")


def _is_cf_challenge(body: str) -> bool:
    if not body: return False
    low = body[:500].lower()
    return any(m in low for m in CF_MARKERS)


class RouteState:
    __slots__ = ("cooldown_until", "consec_429", "circuit_open_until",
                 "inflight", "consec_fail", "dead_until")
    def __init__(self):
        self.cooldown_until = 0.0
        self.consec_429 = 0
        self.circuit_open_until = 0.0
        self.inflight = 0
        self.consec_fail = 0
        self.dead_until = 0.0

    def is_dead(self): return time.monotonic() < self.dead_until
    def mark_fail(self):
        self.consec_fail += 1
        if self.consec_fail >= PROXY_DEAD_STRIKES:
            self.dead_until = time.monotonic() + PROXY_DEAD_COOLDOWN
            self.consec_fail = 0
    def mark_ok(self): self.consec_fail = 0


class SessionHolder:
    __slots__ = ("session", "req_count", "proxy", "host", "backend")
    def __init__(self, session, proxy, host, backend):
        self.session = session
        self.proxy = proxy
        self.host = host
        self.backend = backend
        self.req_count = 0


class BucketTracker:
    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def update_from_headers(self, headers) -> None:
        try:
            bucket = headers.get("x-ratelimit-bucket")
            if not bucket: return
            remaining = headers.get("x-ratelimit-remaining")
            reset_after = headers.get("x-ratelimit-reset-after")
            if remaining is None or reset_after is None: return
            remaining = int(remaining)
            reset_after = float(reset_after)
            with self._lock:
                if len(self._buckets) >= BUCKET_TRACK_MAX:
                    self._buckets.clear()
                self._buckets[bucket] = {
                    "remaining": remaining,
                    "reset_at": time.monotonic() + reset_after,
                }
        except Exception:
            pass

    def should_back_off(self) -> float:
        with self._lock:
            now = time.monotonic()
            max_wait = 0.0
            for b, data in self._buckets.items():
                if data["reset_at"] <= now: continue
                if data["remaining"] <= max(1, int(RATELIMIT_SAFETY_PCT * 5)):
                    w = data["reset_at"] - now
                    if w > max_wait: max_wait = w
            return max_wait


class Checker:
    def __init__(self, timeout_ms: int, proxies: list):
        self.timeout = timeout_ms / 1000.0
        self.proxies = proxies
        self.route_index = 0
        self.lock = threading.Lock()
        self.local = threading.local()
        self.routes = {p: RouteState() for p in proxies}
        self.routes_lock = threading.Lock()
        self.buckets = BucketTracker()
        if not HAS_CURL_CFFI:
            print(f"{YELLOW}WARNING: curl_cffi not installed.{RESET}")
            time.sleep(2)

    @staticmethod
    def _new_session(proxy, host):
        headers = _build_headers(host)
        if HAS_CURL_CFFI:
            s = CurlSession(impersonate=random.choice(IMPERSONATE_PROFILES))
            if proxy: s.proxies = {"http": proxy, "https": proxy}
            s.headers.update(headers)
            return s, "curl_cffi"
        elif HAS_TLS_CLIENT:
            ident = random.choice(["chrome_110", "chrome_116", "chrome_119", "chrome_120"])
            s = tls_client.Session(client_identifier=ident, random_tls_extension_order=True)
            if proxy: s.proxies = {"http": proxy, "https": proxy}
            s.headers.update(headers)
            return s, "tls_client"
        else:
            s = std_requests.Session()
            s.trust_env = False
            from requests.adapters import HTTPAdapter
            adapter = HTTPAdapter(pool_connections=24, pool_maxsize=24, max_retries=0)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
            s.headers.update(headers)
            if proxy: s.proxies.update({"http": proxy, "https": proxy})
            return s, "requests"

    @staticmethod
    def _seed_cf(session, host):
        try: session.get(host + "/", timeout=6, allow_redirects=True)
        except Exception: pass

    def _route_state(self, proxy):
        with self.routes_lock:
            rs = self.routes.get(proxy)
            if rs is None:
                rs = RouteState(); self.routes[proxy] = rs
            return rs

    def _pick(self):
        if not self.proxies: return None, None, None
        bucket_wait = self.buckets.should_back_off()
        if bucket_wait > 0:
            time.sleep(min(bucket_wait, 2.0))
        now = time.monotonic()
        with self.lock:
            n = len(self.proxies); start = self.route_index
            self.route_index += 1
        chosen = None; best_wait = None
        for i in range(n):
            p = self.proxies[(start + i) % n]
            rs = self._route_state(p)
            if rs.is_dead() or rs.inflight >= MAX_PER_ROUTE: continue
            if rs.cooldown_until <= now and rs.circuit_open_until <= now:
                chosen = p; break
            w = max(rs.cooldown_until, rs.circuit_open_until) - now
            if best_wait is None or w < best_wait:
                best_wait = w; chosen = p
        if chosen is None:
            chosen = min(self.proxies,
                         key=lambda x: max(self._route_state(x).dead_until,
                                           self._route_state(x).cooldown_until,
                                           self._route_state(x).circuit_open_until))
        rs = self._route_state(chosen)
        with self.routes_lock: rs.inflight += 1
        host = random.choice(DISCORD_HOSTS)
        holders = getattr(self.local, "holders", None)
        if holders is None:
            holders = {}; self.local.holders = holders
        key = (chosen, host)
        holder = holders.get(key)
        if holder is None or holder.req_count >= SESSION_MAX_REQUESTS:
            if holder is not None:
                try: holder.session.close()
                except Exception: pass
            sess, backend = self._new_session(chosen, host)
            self._seed_cf(sess, host)
            holder = SessionHolder(sess, chosen, host, backend)
            holders[key] = holder
        return holder, chosen, host

    def _release(self, proxy):
        if proxy is None: return
        rs = self._route_state(proxy)
        with self.routes_lock:
            if rs.inflight > 0: rs.inflight -= 1

    def _drop_holder(self, holder):
        if holder is None: return
        holders = getattr(self.local, "holders", None)
        if not holders: return
        holders.pop((holder.proxy, holder.host), None)
        try: holder.session.close()
        except Exception: pass

    def _mark_429(self, proxy):
        rs = self._route_state(proxy)
        with self.routes_lock:
            rs.consec_429 += 1
            now = time.monotonic()
            if rs.consec_429 >= CIRCUIT_BREAK_THRESHOLD:
                rs.circuit_open_until = now + CIRCUIT_BREAK_SEC
                rs.consec_429 = 0
            else:
                rs.cooldown_until = now + ROUTE_COOLDOWN

    def _mark_ok(self, proxy):
        rs = self._route_state(proxy)
        with self.routes_lock:
            rs.consec_429 = 0; rs.mark_ok()

    def _mark_fail(self, proxy):
        rs = self._route_state(proxy)
        with self.routes_lock: rs.mark_fail()

    def check(self, username):
        holder, proxy, host = self._pick()
        if holder is None:
            return CheckResult("error", detail="no live proxy")
        url = host + DISCORD_PATH
        holder.req_count += 1
        try:
            start = time.perf_counter()
            try:
                r = holder.session.post(url, json={"username": username}, timeout=self.timeout)
            except Exception as e:
                self._drop_holder(holder); self._mark_fail(proxy)
                return CheckResult("error", detail=str(e)[:120])
            latency = (time.perf_counter() - start) * 1000
            status = r.status_code
            try: self.buckets.update_from_headers(r.headers)
            except Exception: pass
            body = ""
            try: body = r.text or ""
            except Exception: pass

            if _is_cf_challenge(body):
                self._mark_429(proxy); self._drop_holder(holder)
                return CheckResult("rate_limited", status or 403, detail="cf", latency_ms=latency)
            if status == 429:
                self._mark_429(proxy); self._drop_holder(holder)
                return CheckResult("rate_limited", 429, latency_ms=latency)
            if status == 407:
                self._drop_holder(holder); self._mark_fail(proxy)
                return CheckResult("error", 407, detail="proxy auth")
            if status in (401, 403):
                self._mark_429(proxy); self._drop_holder(holder)
                return CheckResult("rate_limited", status, latency_ms=latency)
            self._mark_ok(proxy)
            try: data = r.json()
            except Exception: return CheckResult("error", status, detail="non-json", latency_ms=latency)
            taken = data.get("taken")
            if isinstance(taken, bool):
                return CheckResult("taken" if taken else "available", status, latency_ms=latency)
            if data.get("rate_limited"):
                self._mark_429(proxy)
                return CheckResult("rate_limited", status, latency_ms=latency)
            self._mark_429(proxy)
            return CheckResult("rate_limited", status, latency_ms=latency)
        finally:
            self._release(proxy)


def _check_one(checker, name):
    last = None
    for _ in range(UNKNOWN_RETRY_ATTEMPTS):
        result = checker.check(name)
        if result.state in ("taken", "available"): return name, result
        last = result
    return name, last


# ═════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═════════════════════════════════════════════════════════════════════════════

def run_checker(base, settings):
    proxies = load_proxies(base, settings)
    if not proxies:
        clear(); banner()
        print(f"\n  {RED}✗ No proxies loaded.{RESET}")
        print(f"  {YELLOW}Add them to {PROXY_FILE} (one per line) or use menu [3].{RESET}\n")
        input("  Press Enter to return..."); return

    effective_cps = settings.target_cps
    checker = Checker(settings.timeout_ms, proxies)
    gen = NameGenerator(settings.mode)
    history = PersistentHistory(base / HISTORY_FILE)
    mode_label = MODE_BY_ID[settings.mode][1]
    workers = worker_count_for(effective_cps, len(proxies))

    webhook_sender = None
    if settings.webhook:
        webhook_sender = WebhookSender(settings.webhook)
        webhook_sender.start()

    clear(); banner()
    print(f"  {WHITE}MODE{RESET}       {mode_label}")
    print(f"  {WHITE}CONNECTION{RESET} {len(proxies)} proxies")
    print(f"  {WHITE}PACE{RESET}       {effective_cps:.1f} CPS    {WHITE}WORKERS{RESET} {workers}")
    print(f"  {WHITE}TOTAL{RESET}      {gen.total:,} combos")
    print("  " + "─" * 58)
    print()

    for i in range(READY_DELAY_SEC, 0, -1):
        print(f"\r  {GREY}Starting in {i}…{RESET}", end="", flush=True)
        time.sleep(1)
    print(f"\r  {GREEN}GO!{RESET}                     ")
    print()

    checked = taken = unknown = available = limited = 0
    results_path = base / RESULTS_FILE
    results_path.parent.mkdir(parents=True, exist_ok=True)

    TAG_TAKEN = f"{RED}TAKEN{RESET}    "
    TAG_AVAILABLE = f"{GREEN}AVAILABLE{RESET}"

    try:
        while True:
            try:
                with results_path.open("a", encoding="utf-8") as results_file, ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix="sniperr"
                ) as pool:
                    inflight = {}
                    next_submit = time.monotonic()
                    while True:
                        now = time.monotonic()
                        while len(inflight) < workers and now >= next_submit:
                            name = gen.next()
                            fut = pool.submit(_check_one, checker, name)
                            inflight[fut] = name
                            interval = 1.0 / max(MIN_CPS, effective_cps)
                            next_submit += interval
                            if next_submit < now - 0.05: next_submit = now
                            now = time.monotonic()
                        if not inflight:
                            time.sleep(0.002); continue
                        done, _ = wait(tuple(inflight), timeout=0.004, return_when=FIRST_COMPLETED)
                        if not done: continue
                        for fut in done:
                            name = inflight.pop(fut, "?")
                            try: _name, result = fut.result()
                            except Exception: continue
                            state = result.state
                            if state == "taken":
                                checked += 1; taken += 1
                                if settings.show_taken:
                                    print(f"{TAG_TAKEN} {name:<20} "
                                          f"{GREY}{format_stats(checked, taken, available, limited)}{RESET}")
                            elif state == "available":
                                checked += 1; available += 1
                                print(f"{TAG_AVAILABLE} {name:<20} "
                                      f"{GREY}{format_stats(checked, taken, available, limited)}{RESET}")
                                try:
                                    results_file.write(name + "\n"); results_file.flush()
                                except OSError: pass
                                try: history.claim(name)
                                except Exception: pass
                                if webhook_sender: webhook_sender.enqueue(name, mode_label)
                            elif state == "rate_limited":
                                checked += 1; taken += 1
                            else:
                                pass
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"{YELLOW} RECOVER   {RESET} {str(exc)[:120]}")
                time.sleep(0.35)
    except KeyboardInterrupt:
        print("\n" + GREY + "Stopped." + RESET)
    finally:
        if webhook_sender: webhook_sender.stop()
        history.close()
        print(format_stats(checked, taken, available, limited))


# ═════════════════════════════════════════════════════════════════════════════
# MENU
# ═════════════════════════════════════════════════════════════════════════════

def looks_like_discord_webhook(url):
    u = url.strip()
    return (u.startswith("https://discord.com/api/webhooks/") or
            u.startswith("https://discordapp.com/api/webhooks/") or
            u.startswith("https://canary.discord.com/api/webhooks/") or
            u.startswith("https://ptb.discord.com/api/webhooks/"))


YIELD_HINT = {
    "semi_3c_both": "low", "semi_3c_dot": "low", "semi_3c_under": "low",
    "semi_3n_both": "low", "semi_3n_dot": "low", "semi_3n_under": "low",
    "semi_4n_both": "med", "semi_4n_dot": "med", "semi_4n_under": "med",
    "2c": "dead", "3c_smart": "dead", "4c_smart": "dead",
    "5c": "~0.3%", "3l": "dead", "4l": "~0.1%", "5l": "~1.5%",
    "3n": "dead", "4n": "~0.05%", "5n": "~0.5%",
    "word_short": "~5%", "word_rare": "~15%", "word_obscure": "~30%",
    "word_all": "~20%", "word_sep": "~25%",
    "word_join": "~25%", "word_dict": "~20%", "word_dict_join": "~30%",
    "word_mega_join": "~35%", "word_num_word": "~50%",
}


def choose_mode(settings):
    clear(); banner()
    print(RED + "\nChoose username type\n" + RESET)
    print(f"{GREY}MIX is the highest-yield — hits within seconds.{RESET}\n")
    for key, (mid, label, example) in MODE_MAP.items():
        marker = GREEN + "*" + RESET if settings.mode == mid else " "
        yh = YIELD_HINT.get(mid, "?")
        star = f"{GREEN}★{RESET}" if mid in ("word_num_word", "word_mega_join",
                                              "word_dict_join", "word_obscure") else " "
        print(f" {marker}{star}[{key:>2}] {label:<22} {GREY}{yh:<12}{RESET} {GREY}{example}{RESET}")
    print(f"\n  {GREEN}★ = best yield{RESET}")
    print("\n  [0] Back")
    val = input("\nSelect: ").strip()
    if val in MODE_MAP: settings.mode = MODE_MAP[val][0]
    elif val.upper() in MODE_MAP: settings.mode = MODE_MAP[val.upper()][0]


def choose_speed(settings):
    print(f"\nCurrent target: {settings.target_cps:.1f} CPS")
    raw = input(f"Target CPS ({MIN_CPS:g}-{MAX_CPS:g}, blank keeps current): ").strip()
    if not raw: return
    try: settings.target_cps = max(MIN_CPS, min(MAX_CPS, float(raw)))
    except ValueError: print(YELLOW + "Invalid CPS." + RESET)


def choose_connection(base, settings):
    while True:
        clear(); banner()
        proxies = load_proxies(base, settings)
        print(RED + "\nConnection\n" + RESET)
        print(f"  [1] Load proxies from {PROXY_FILE} ({len(proxies)} found)")
        print("  [2] Paste proxy/proxy list now")
        print("  [0] Back")
        choice = input("\nSelect: ").strip()
        if choice == "0": return
        if choice == "1":
            settings.proxies = ""
            print(GREEN + f"Using {len(load_proxies(base, settings))} proxies.{RESET}")
            input("Press Enter...")
        elif choice == "2":
            print("Paste proxies. One per line. Blank line when done.")
            rows = []
            while True:
                row = input().strip()
                if not row: break
                rows.append(row)
            settings.proxies = "\n".join(rows)
            print(GREEN + f"Stored {len(rows)} proxies.{RESET}")
            input("Press Enter...")


def choose_webhook(settings):
    clear(); banner(); print(RED + "\nDiscord webhook\n" + RESET)
    if settings.webhook:
        print(f"{GREY}Current: {_mask_url(settings.webhook)}{RESET}\n")
    print("  [1] Set / replace webhook URL")
    print("  [2] Send test")
    print("  [3] Clear webhook")
    print("  [0] Back")
    ch = input("\nSelect: ").strip()
    if ch == "1":
        url = input("Paste Discord webhook URL: ").strip()
        if not looks_like_discord_webhook(url):
            print(YELLOW + "Invalid webhook URL." + RESET)
            input("Press Enter..."); return
        settings.webhook = url
        print(GREEN + "Webhook saved." + RESET)
        ok, _b, err = _try_send_webhook(url, "sniperr_test", "Test")
        print((GREEN + "✓ Test sent." if ok else RED + f"✗ Failed: {err}") + RESET)
        input("Press Enter...")
    elif ch == "2":
        if not settings.webhook:
            print(YELLOW + "Set a webhook first." + RESET); input("Press Enter..."); return
        ok, _b, err = _try_send_webhook(settings.webhook, "test", "Test")
        print((GREEN + "✓ Sent." if ok else RED + f"✗ {err}") + RESET)
        input("Press Enter...")
    elif ch == "3":
        settings.webhook = ""


def print_status(settings, proxies, history_count):
    mode = MODE_BY_ID[settings.mode][1]
    conn = f"{len(proxies)} proxies" if proxies else f"{RED}NO PROXIES{RESET}"
    wh = "enabled" if settings.webhook else "disabled"
    print(GREY + f"Mode: {mode} | Connection: {conn} | Webhook: {wh} | History: {history_count}" + RESET)


def main():
    enable_ansi()
    base = Path(__file__).resolve().parent
    settings = load_settings(base)

    while True:
        clear(); banner()
        proxies = load_proxies(base, settings)
        print_status(settings, proxies, history_count=0)
        print()
        print("  [1] Start checker")
        print("  [2] Choose username type")
        print("  [3] Choose connection / proxies")
        print("  [4] Target CPS")
        print("  [5] Discord webhook")
        print("  [6] Save current settings")
        print("  [7] Toggle show TAKEN")
        print("  [0] Exit")
        print()
        choice = input("Select: ").strip()

        if choice == "0": return
        if choice == "1": run_checker(base, settings)
        elif choice == "2": choose_mode(settings)
        elif choice == "3": choose_connection(base, settings)
        elif choice == "4": choose_speed(settings)
        elif choice == "5": choose_webhook(settings)
        elif choice == "6":
            save_settings(base, settings)
            print(GREEN + "Settings saved." + RESET)
            time.sleep(0.8)
        elif choice == "7":
            settings.show_taken = not settings.show_taken


class _EmbeddedEngine:
    pass

engine = _EmbeddedEngine()
for _name in (
    "MAX_WORKERS", "normalize_proxy", "NameGenerator", "DEFAULT_TIMEOUT_MS",
    "Checker", "DEFAULT_CPS", "MIN_CPS", "looks_like_discord_webhook",
    "WebhookSender", "_check_one", "CheckResult"
):
    setattr(engine, _name, globals()[_name])
del _name

import json
import os
import queue
import subprocess
import threading
import time
import webbrowser
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any, Callable, Optional


BASE = Path(__file__).resolve().parent
_state_root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".sniperr")) / "Sniperr"
try:
    _state_root.mkdir(parents=True, exist_ok=True)
except OSError:
    _state_root = Path.home()
STATE_FILE = _state_root / "sniperr-ui-state.json"
INDEX_BYTES = base64.b64decode("PGh0bWwgbGFuZz0iZW4iPgo8aGVhZD4KPG1ldGEgY2hhcnNldD0idXRmLTgiIC8+CjxtZXRhIGh0dHAtZXF1aXY9IlgtVUEtQ29tcGF0aWJsZSIgY29udGVudD0iSUU9ZWRnZSIgLz4KPHRpdGxlPlNOSVBFUlIgQ2hlY2tlcjwvdGl0bGU+CjxsaW5rIHJlbD0icHJlY29ubmVjdCIgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbSIgLz4KPGxpbmsgcmVsPSJwcmVjb25uZWN0IiBocmVmPSJodHRwczovL2ZvbnRzLmdzdGF0aWMuY29tIiBjcm9zc29yaWdpbiAvPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PUlCTStQbGV4K01vbm86d2dodEA0MDA7NTAwJmZhbWlseT1PdXRmaXQ6d2dodEA0MDA7NTAwOzYwMDs3MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQiIC8+CjxzdHlsZT4KICA6cm9vdCB7CiAgICAtLWJnOiAjMDcwOTA4OyAtLWVsZXY6ICMwYjBlMGM7IC0tc3VyZjogIzEwMTQxMjsgLS1zdXJmMjogIzE2MWMxOTsKICAgIC0tZmc6ICNlZWYzZjA7IC0tbXV0ZWQ6ICM5YWEzOWQ7IC0tc3VidGxlOiAjNmE3MzZlOwogICAgLS1hY2NlbnQ6ICMyZWU1OWQ7IC0tYWNjZW50LWZnOiAjMDQyMDE2OyAtLWFjY2VudC1kaW06ICMxMTM1MmE7CiAgICAtLWJvcmRlcjogcmdiYSgyMzgsMjQzLDI0MCwuMTApOyAtLWJvcmRlci1zdHJvbmc6IHJnYmEoMjM4LDI0MywyNDAsLjE2KTsKICAgIC0tZGFuZ2VyOiAjZTA3MDcwOyAtLXRha2VuOiAjYzQ1YzVjOyAtLXdhcm46ICNkN2I1NmE7CiAgICAtLXJhZGl1czogMTZweDsgLS1yYWRpdXMteGw6IDI0cHg7CiAgICAtLWVhc2U6IGN1YmljLWJlemllciguMjIsMSwuMzYsMSk7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgaHRtbCwgYm9keSwgKiB7CiAgICB1c2VyLXNlbGVjdDogbm9uZTsKICAgIC13ZWJraXQtdXNlci1zZWxlY3Q6IG5vbmU7CiAgICAtd2Via2l0LXRvdWNoLWNhbGxvdXQ6IG5vbmU7CiAgfQogIGlucHV0Om5vdChbdHlwZT1jaGVja2JveF0pLCB0ZXh0YXJlYSB7CiAgICB1c2VyLXNlbGVjdDogdGV4dDsKICAgIC13ZWJraXQtdXNlci1zZWxlY3Q6IHRleHQ7CiAgfQogIDo6c2VsZWN0aW9uIHsgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7IGNvbG9yOiBpbmhlcml0OyB9CiAgaW5wdXQ6OnNlbGVjdGlvbiwgdGV4dGFyZWE6OnNlbGVjdGlvbiB7CiAgICBiYWNrZ3JvdW5kOiBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudCkgMzUlLCB0cmFuc3BhcmVudCk7CiAgICBjb2xvcjogdmFyKC0tZmcpOwogIH0KICBodG1sLCBib2R5IHsKICAgIG1hcmdpbjogMDsgaGVpZ2h0OiAxMDAlOyBvdmVyZmxvdzogaGlkZGVuOyBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7IGNvbG9yOiB2YXIoLS1mZyk7CiAgICBmb250OiAxNXB4LzEuNSBPdXRmaXQsICJTZWdvZSBVSSIsIHN5c3RlbS11aSwgc2Fucy1zZXJpZjsKICAgIC13ZWJraXQtZm9udC1zbW9vdGhpbmc6IGFudGlhbGlhc2VkOwogICAgLXdlYmtpdC1hcHAtcmVnaW9uOiBuby1kcmFnOyBhcHAtcmVnaW9uOiBuby1kcmFnOwogICAgY29sb3Itc2NoZW1lOiBkYXJrOwogIH0KICAqIHsKICAgIHNjcm9sbGJhci13aWR0aDogdGhpbjsKICAgIHNjcm9sbGJhci1jb2xvcjogIzJlZTU5ZDU1IHRyYW5zcGFyZW50OwogIH0KICAqOjotd2Via2l0LXNjcm9sbGJhciB7IHdpZHRoOiA4cHg7IGhlaWdodDogOHB4OyB9CiAgKjo6LXdlYmtpdC1zY3JvbGxiYXItdHJhY2sgeyBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsgfQogICo6Oi13ZWJraXQtc2Nyb2xsYmFyLXRodW1iIHsKICAgIGJhY2tncm91bmQ6IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tZmcpIDE2JSwgdHJhbnNwYXJlbnQpOwogICAgYm9yZGVyLXJhZGl1czogOTlweDsKICAgIGJvcmRlcjogMnB4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgYmFja2dyb3VuZC1jbGlwOiBwYWRkaW5nLWJveDsKICB9CiAgKjo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWI6aG92ZXIgewogICAgYmFja2dyb3VuZDogY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDU1JSwgdHJhbnNwYXJlbnQpOwogICAgYmFja2dyb3VuZC1jbGlwOiBwYWRkaW5nLWJveDsKICB9CiAgKjo6LXdlYmtpdC1zY3JvbGxiYXItY29ybmVyIHsgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7IH0KICBidXR0b24geyBjdXJzb3I6IHBvaW50ZXI7IGZvbnQ6IGluaGVyaXQ7IH0KICBidXR0b246ZGlzYWJsZWQgeyBvcGFjaXR5OiAuNDsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgYnV0dG9uOm5vdCg6ZGlzYWJsZWQpOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoLjk4KTsgfQogIGlucHV0Om5vdChbdHlwZT1jaGVja2JveF0pLCB0ZXh0YXJlYSB7CiAgICBmb250OiBpbmhlcml0OyBjb2xvcjogdmFyKC0tZmcpOyBiYWNrZ3JvdW5kOiAjMGEwZTBjOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogMTJweDsgcGFkZGluZzogMCAxNHB4OyBvdXRsaW5lOiBub25lOwogICAgdHJhbnNpdGlvbjogYm9yZGVyLWNvbG9yIDE1MG1zIHZhcigtLWVhc2UpLCBib3gtc2hhZG93IDE1MG1zIHZhcigtLWVhc2UpOwogIH0KICBpbnB1dDpub3QoW3R5cGU9Y2hlY2tib3hdKTpmb2N1cywgdGV4dGFyZWE6Zm9jdXMgewogICAgYm9yZGVyLWNvbG9yOiBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudCkgNjIlLCB0cmFuc3BhcmVudCk7CiAgICBib3gtc2hhZG93OiAwIDAgMCAzcHggY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDE2JSwgdHJhbnNwYXJlbnQpOwogIH0KICBpbnB1dFt0eXBlPWNoZWNrYm94XSB7CiAgICBhcHBlYXJhbmNlOiBhdXRvOwogICAgd2lkdGg6IDE0cHg7IGhlaWdodDogMTRweDsgbWFyZ2luOiAwIDhweCAwIDA7IHBhZGRpbmc6IDA7CiAgICBib3JkZXI6IDA7IGJvcmRlci1yYWRpdXM6IDA7IGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OwogICAgYm94LXNoYWRvdzogbm9uZTsgb3V0bGluZTogbm9uZTsgYWNjZW50LWNvbG9yOiB2YXIoLS1hY2NlbnQpOwogICAgdXNlci1zZWxlY3Q6IG5vbmU7IC13ZWJraXQtdXNlci1zZWxlY3Q6IG5vbmU7CiAgfQogIGlucHV0W3R5cGU9Y2hlY2tib3hdOmZvY3VzLAogIGlucHV0W3R5cGU9Y2hlY2tib3hdOmZvY3VzLXZpc2libGUgewogICAgb3V0bGluZTogbm9uZTsKICAgIGJveC1zaGFkb3c6IG5vbmU7CiAgICBib3JkZXI6IDA7CiAgfQogIGlucHV0W3R5cGU9bnVtYmVyXTo6LXdlYmtpdC1vdXRlci1zcGluLWJ1dHRvbiwKICBpbnB1dFt0eXBlPW51bWJlcl06Oi13ZWJraXQtaW5uZXItc3Bpbi1idXR0b24geyAtd2Via2l0LWFwcGVhcmFuY2U6IG5vbmU7IG1hcmdpbjogMDsgfQogIGlucHV0W3R5cGU9bnVtYmVyXSB7IC1tb3otYXBwZWFyYW5jZTogdGV4dGZpZWxkOyBhcHBlYXJhbmNlOiB0ZXh0ZmllbGQ7IH0KICAua2lja2VyIHsgZm9udC1zaXplOiAxMXB4OyBmb250LXdlaWdodDogNTAwOyBsZXR0ZXItc3BhY2luZzogLjE4ZW07IHRleHQtdHJhbnNmb3JtOiB1cHBlcmNhc2U7IGNvbG9yOiB2YXIoLS1zdWJ0bGUpOyB9CiAgLmJ0biB7CiAgICBoZWlnaHQ6IDQ0cHg7IGJvcmRlcjogMDsgYm9yZGVyLXJhZGl1czogMTJweDsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHZhcigtLWFjY2VudC1mZyk7CiAgICBmb250LXdlaWdodDogNjAwOyBwYWRkaW5nOiAwIDE4cHg7IHBvc2l0aW9uOiByZWxhdGl2ZTsgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRyYW5zaXRpb246IGZpbHRlciAxNTBtcyB2YXIoLS1lYXNlKSwgdHJhbnNmb3JtIDE1MG1zIHZhcigtLWVhc2UpOwogIH0KICAuYnRuIHsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogIC5idG46OmFmdGVyIHsKICAgIGNvbnRlbnQ6IiI7IHBvc2l0aW9uOmFic29sdXRlOyBpbnNldDowIGF1dG8gMCAtNDAlOyB3aWR0aDo0MCU7CiAgICBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoOTBkZWcsIHRyYW5zcGFyZW50LCByZ2JhKDI1NSwyNTUsMjU1LC4xOCksIHRyYW5zcGFyZW50KTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtMTIwJSk7CiAgfQogIC5idG46aG92ZXI6bm90KDpkaXNhYmxlZCk6OmFmdGVyIHsgYW5pbWF0aW9uOiBzaGVlbiAuN3MgdmFyKC0tZWFzZSk7IH0KICAuY2hpcCB7IGFuaW1hdGlvbjogbm9uZTsgfQogIC5tb2QgeyBhbmltYXRpb246IG5vbmU7IH0KICAuc3RhdCB7IGFuaW1hdGlvbjogbm9uZTsgfQogIC5oaXQgeyB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMTYwbXMgdmFyKC0tZWFzZSksIGJvcmRlci1jb2xvciAxNjBtcyB2YXIoLS1lYXNlKTsgfQogIC5oaXQ6aG92ZXIgeyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMnB4KTsgfQogIC5zY2FuIGkgeyBmaWx0ZXI6IGRyb3Atc2hhZG93KDAgMCA2cHggY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDcwJSwgdHJhbnNwYXJlbnQpKTsgfQogIC5idG4uZ2hvc3QgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmMik7IGNvbG9yOiB2YXIoLS1mZyk7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuYnRuLmxnIHsgaGVpZ2h0OiA0OHB4OyBmb250LXNpemU6IDE1cHg7IG1pbi13aWR0aDogMTMycHg7IH0KICAucGFuZWwgewogICAgcG9zaXRpb246IHJlbGF0aXZlOwogICAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDE4MGRlZywgY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1zdXJmKSA5MiUsIHdoaXRlIDQlKSwgdmFyKC0tc3VyZikpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzLXhsKTsKICAgIGJveC1zaGFkb3c6IGluc2V0IDAgMXB4IDAgcmdiYSgyNTUsMjU1LDI1NSwuMDQpLCAwIDI0cHggNDhweCAtMzZweCByZ2JhKDAsMCwwLC43KTsKICB9CiAgLnBhbmVsOjpiZWZvcmUgewogICAgY29udGVudDogIiI7IHBvc2l0aW9uOiBhYnNvbHV0ZTsgaW5zZXQ6IDAgMTglIGF1dG87IGhlaWdodDogMXB4OyBwb2ludGVyLWV2ZW50czogbm9uZTsKICAgIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCg5MGRlZywgdHJhbnNwYXJlbnQsIGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSA1NSUsIHRyYW5zcGFyZW50KSwgdHJhbnNwYXJlbnQpOwogIH0KICAudGFicyB7IGRpc3BsYXk6ZmxleDsgZ2FwOjRweDsgbWFyZ2luOiAwIDAgMTZweDsgcGFkZGluZzo0cHg7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOjEycHg7IH0KICAudGFicyBidXR0b24geyBmbGV4OjE7IGhlaWdodDozNnB4OyBib3JkZXI6MDsgYm9yZGVyLXJhZGl1czoxMHB4OyBiYWNrZ3JvdW5kOnRyYW5zcGFyZW50OyBjb2xvcjp2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OjYwMDsgdHJhbnNmb3JtOm5vbmU7IH0KICAudGFicyBidXR0b24ub24geyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQtZGltKTsgY29sb3I6IHZhcigtLWZnKTsgfQogIC50YiB7IGRpc3BsYXk6IG5vbmUgIWltcG9ydGFudDsgfQogIC50YiAud2luLCAudGIgLndpbiBidXR0b24geyBjdXJzb3I6IGRlZmF1bHQ7IH0KICAudGIgLmJyYW5kIHsgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDo4cHg7IHBvaW50ZXItZXZlbnRzOm5vbmU7IH0KICAudGIgLmJyYW5kIC5tYXJrIHsgd2lkdGg6MTZweDsgaGVpZ2h0OjE2cHg7IGRpc3BsYXk6YmxvY2s7IGJvcmRlci1yYWRpdXM6NHB4OyB9CiAgLnRiIC5icmFuZCBiIHsgZm9udC1zaXplOiAxMXB4OyBmb250LXdlaWdodDogNzAwOyBsZXR0ZXItc3BhY2luZzogLjE4ZW07IGNvbG9yOiB2YXIoLS1mZyk7IH0KICAudGIgLndpbiB7IGRpc3BsYXk6ZmxleDsgaGVpZ2h0OjEwMCU7IH0KICAudGIgLndpbiBidXR0b24gewogICAgd2lkdGg6NDZweDsgaGVpZ2h0OjM4cHg7IGJvcmRlcjowOyBiYWNrZ3JvdW5kOnRyYW5zcGFyZW50OyBjb2xvcjp2YXIoLS1tdXRlZCk7CiAgICBib3JkZXItcmFkaXVzOjA7IGZvbnQtc2l6ZToxM3B4OyB0cmFuc2Zvcm06IG5vbmU7IGxpbmUtaGVpZ2h0OjE7CiAgfQogIC50YiAud2luIGJ1dHRvbjpob3ZlciB7IGJhY2tncm91bmQ6IzFjMjMxZjsgY29sb3I6dmFyKC0tZmcpOyB9CiAgLnRiIC53aW4gYnV0dG9uLng6aG92ZXIgeyBiYWNrZ3JvdW5kOiM5YjJjMmM7IGNvbG9yOiNmZmY7IH0KICAuc2hlbGwgeyBoZWlnaHQ6IDEwMCU7IGRpc3BsYXk6ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1uOyB9CiAgLndhc2ggewogICAgcG9zaXRpb246IGFic29sdXRlOyBpbnNldDogMDsgcG9pbnRlci1ldmVudHM6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOgogICAgICByYWRpYWwtZ3JhZGllbnQoNzAlIDQ2JSBhdCA1MCUgLTEyJSwgY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDE2JSwgdHJhbnNwYXJlbnQpLCB0cmFuc3BhcmVudCA2MiUpLAogICAgICByYWRpYWwtZ3JhZGllbnQoNDIlIDM0JSBhdCA4JSAxOCUsIGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSA3JSwgdHJhbnNwYXJlbnQpLCB0cmFuc3BhcmVudCA3MCUpLAogICAgICByYWRpYWwtZ3JhZGllbnQoNDglIDM4JSBhdCA5NiUgMTA4JSwgY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDglLCB0cmFuc3BhcmVudCksIHRyYW5zcGFyZW50IDY4JSksCiAgICAgIGxpbmVhci1ncmFkaWVudCgxODBkZWcsICMwYjEwMGUgMCUsIHZhcigtLWJnKSA0OCUsICMwNTA3MDYgMTAwJSk7CiAgfQogIC5ncmlkYmcgewogICAgcG9zaXRpb246IGFic29sdXRlOyBpbnNldDogMDsgcG9pbnRlci1ldmVudHM6IG5vbmU7CiAgICBiYWNrZ3JvdW5kLWltYWdlOgogICAgICBsaW5lYXItZ3JhZGllbnQocmdiYSgyMzgsMjQzLDI0MCwuMDQ1KSAxcHgsIHRyYW5zcGFyZW50IDFweCksCiAgICAgIGxpbmVhci1ncmFkaWVudCg5MGRlZywgcmdiYSgyMzgsMjQzLDI0MCwuMDQ1KSAxcHgsIHRyYW5zcGFyZW50IDFweCk7CiAgICBiYWNrZ3JvdW5kLXNpemU6IDU2cHggNTZweDsKICAgIG1hc2staW1hZ2U6IHJhZGlhbC1ncmFkaWVudCg3OCUgNjglIGF0IDUwJSAyOCUsICMwMDAgMTglLCB0cmFuc3BhcmVudCA3OCUpOwogICAgYW5pbWF0aW9uOiBkcmlmdCA0OHMgbGluZWFyIGluZmluaXRlOwogIH0KICAuZ2F0ZSwgLnNldHVwIHsKICAgIHBvc2l0aW9uOiByZWxhdGl2ZTsgZmxleDoxOyBtaW4taGVpZ2h0OjA7IGRpc3BsYXk6IGdyaWQ7IHBsYWNlLWl0ZW1zOiBjZW50ZXI7IHBhZGRpbmc6IDI4cHggMjRweDsgb3ZlcmZsb3c6YXV0bzsKICB9CiAgLmdhdGUtY2FyZCB7IHdpZHRoOiAxMDAlOyBtYXgtd2lkdGg6IDQyMHB4OyBwb3NpdGlvbjogcmVsYXRpdmU7IGFuaW1hdGlvbjogcmlzZSAuNDJzIHZhcigtLWVhc2UpIGJvdGg7IH0KICAud20geyB1c2VyLXNlbGVjdDpub25lOyB9CiAgLndtLmhlcm8geyB0ZXh0LWFsaWduOmNlbnRlcjsgbWFyZ2luOiAwIGF1dG8gMjJweDsgfQogIC53bS1uYW1lIHsgZm9udC13ZWlnaHQ6NzAwOyBsZXR0ZXItc3BhY2luZzouMDRlbTsgbGluZS1oZWlnaHQ6MTsgfQogIC53bS1uYW1lIHNwYW4geyBjb2xvcjogdmFyKC0tYWNjZW50KTsgfQogIC53bS1zdWIgeyBmb250LXNpemU6MTBweDsgbGV0dGVyLXNwYWNpbmc6LjM0ZW07IGNvbG9yOnZhcigtLXN1YnRsZSk7IG1hcmdpbi10b3A6OHB4OyBmb250LXdlaWdodDo1MDA7IH0KICAud20uaGVybyAud20tbmFtZSB7IGZvbnQtc2l6ZTo1MnB4OyB9CiAgLndtLnNpZGUgewogICAgbWFyZ2luOiAyMHB4IDE2cHggNHB4OwogICAgcGFkZGluZzogOHB4IDRweCAxNHB4OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgfQogIC53bS5zaWRlIC53bS1uYW1lIHsgZm9udC1zaXplOiA0NHB4OyBsZXR0ZXItc3BhY2luZzogLjA2ZW07IGZvbnQtd2VpZ2h0OiA3MDA7IH0KICAud20uc2lkZSAud20tc3ViIHsKICAgIG1hcmdpbi10b3A6IDhweDsKICAgIGxldHRlci1zcGFjaW5nOiAuNDJlbTsKICAgIGZvbnQtc2l6ZTogMTFweDsKICAgIHBhZGRpbmctbGVmdDogLjQyZW07CiAgfQogIC53bS5zaWRlOjphZnRlciB7CiAgICBjb250ZW50OiAiIjsKICAgIGRpc3BsYXk6IGJsb2NrOwogICAgd2lkdGg6IDY0cHg7CiAgICBoZWlnaHQ6IDFweDsKICAgIG1hcmdpbi10b3A6IDEycHg7CiAgICBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoOTBkZWcsIHRyYW5zcGFyZW50LCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudCkgODAlLCB0cmFuc3BhcmVudCksIHRyYW5zcGFyZW50KTsKICB9CiAgLndtLnNldHVwIHsgbWFyZ2luOiAwIDAgMThweDsgdGV4dC1hbGlnbjpjZW50ZXI7IH0KICAud20uc2V0dXAgLndtLW5hbWUgeyBmb250LXNpemU6NDBweDsgfQogIC5maWVsZCB7IHdpZHRoOiAxMDAlOyBoZWlnaHQ6IDQ0cHg7IG1hcmdpbi10b3A6IDZweDsgfQogIGlucHV0LmxvY2tlZCB7IG9wYWNpdHk6IC43MjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmF0IHsKICAgIGRpc3BsYXk6ZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBoZWlnaHQ6NDRweDsgbWFyZ2luLXRvcDo2cHg7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6MTJweDsgYmFja2dyb3VuZDojMGEwZTBjOyBvdmVyZmxvdzpoaWRkZW47CiAgICB0cmFuc2l0aW9uOiBib3JkZXItY29sb3IgMTUwbXMgdmFyKC0tZWFzZSksIGJveC1zaGFkb3cgMTUwbXMgdmFyKC0tZWFzZSk7CiAgfQogIC5hdDpmb2N1cy13aXRoaW4gewogICAgYm9yZGVyLWNvbG9yOiBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudCkgNjIlLCB0cmFuc3BhcmVudCk7CiAgICBib3gtc2hhZG93OiAwIDAgMCAzcHggY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDE2JSwgdHJhbnNwYXJlbnQpOwogIH0KICAuYXQgc3BhbiB7IHBhZGRpbmc6MCAycHggMCAxNHB4OyBjb2xvcjp2YXIoLS1hY2NlbnQpOyBmb250LXdlaWdodDo3MDA7IGZvbnQtc2l6ZToxNnB4OyB1c2VyLXNlbGVjdDpub25lOyB9CiAgLmF0IGlucHV0IHsgYm9yZGVyOjA7IGJhY2tncm91bmQ6dHJhbnNwYXJlbnQ7IGhlaWdodDoxMDAlOyBmbGV4OjE7IG1pbi13aWR0aDowOyBwYWRkaW5nOjAgMTRweCAwIDJweDsgYm94LXNoYWRvdzpub25lOyBib3JkZXItcmFkaXVzOjA7IH0KICAuZXJyIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IGZvbnQtc2l6ZTogMTRweDsgbWFyZ2luOiAxMHB4IDAgMDsgfQogIC5hcHAgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGRpc3BsYXk6IGZsZXg7IGZsZXg6MTsgbWluLWhlaWdodDowOyBvdmVyZmxvdzpoaWRkZW47IH0KICBhc2lkZSB7CiAgICB3aWR0aDogMjcycHg7IGJhY2tncm91bmQ6IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tZWxldikgODglLCB0cmFuc3BhcmVudCk7CiAgICBib3JkZXItcmlnaHQ6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyB1c2VyLXNlbGVjdDpub25lOyB6LWluZGV4OjE7CiAgfQogIC53aG8geyBkaXNwbGF5OiBmbGV4OyBnYXA6IDEwcHg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IHBhZGRpbmc6IDE0cHggMTZweDsgfQogIC53aG8gaW1nLCAud2hvIC5waCB7CiAgICB3aWR0aDogNDBweDsgaGVpZ2h0OiA0MHB4OyBib3JkZXItcmFkaXVzOiA1MCU7IG9iamVjdC1maXQ6IGNvdmVyOyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQtZGltKTsgY29sb3I6IHZhcigtLWFjY2VudCk7CiAgICBkaXNwbGF5OiBncmlkOyBwbGFjZS1pdGVtczogY2VudGVyOyBmb250LXdlaWdodDogNjAwOyBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIG5hdiBidXR0b24gewogICAgd2lkdGg6IGNhbGMoMTAwJSAtIDE2cHgpOyBtYXJnaW46IDJweCA4cHg7IHRleHQtYWxpZ246IGxlZnQ7IGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OyBjb2xvcjogdmFyKC0tbXV0ZWQpOwogICAgYm9yZGVyOiAwOyBib3JkZXItcmFkaXVzOiAxMHB4OyBwYWRkaW5nOiA5cHggMTJweDsgcG9zaXRpb246IHJlbGF0aXZlOwogICAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAxNTBtcyB2YXIoLS1lYXNlKSwgY29sb3IgMTUwbXMgdmFyKC0tZWFzZSksIHRyYW5zZm9ybSAxNTBtcyB2YXIoLS1lYXNlKTsKICB9CiAgbmF2IGJ1dHRvbjpob3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmYpOyBjb2xvcjogdmFyKC0tZmcpOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMXB4KTsgfQogIG5hdiBidXR0b24ub24geyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQtZGltKTsgY29sb3I6IHZhcigtLWZnKTsgfQogIG5hdiBidXR0b24ub246OmJlZm9yZSB7CiAgICBjb250ZW50OiIiOyBwb3NpdGlvbjphYnNvbHV0ZTsgbGVmdDowOyB0b3A6NTAlOyB3aWR0aDoycHg7IGhlaWdodDoxNnB4OyBib3JkZXItcmFkaXVzOjk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoLTUwJSk7CiAgfQogIG5hdiBidXR0b24uc29vbiB7IG9wYWNpdHk6IC43MjsgfQogIG5hdiBidXR0b24uc29vbjpob3ZlciB7IGNvbG9yOiB2YXIoLS1mZyk7IH0KICBuYXYgYnV0dG9uIC5zb29uLXRhZyB7CiAgICBwb3NpdGlvbjphYnNvbHV0ZTsgcmlnaHQ6MTBweDsgdG9wOjUwJTsgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC01MCUpOwogICAgZm9udC1zaXplOjlweDsgbGV0dGVyLXNwYWNpbmc6LjEyZW07IHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsgY29sb3I6IHZhcigtLXdhcm4pOwogIH0KICBtYWluIHsgZmxleDogMTsgcGFkZGluZzogMjhweCAzMnB4OyBvdmVyZmxvdzogYXV0bzsgcG9zaXRpb246IHJlbGF0aXZlOyB6LWluZGV4OjE7IH0KICAubW9kZXMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdCg1LCBtaW5tYXgoMCwgMWZyKSk7IGdhcDogMTBweDsgfQogIC5saXN0cyB7IGRpc3BsYXk6ZmxleDsgZmxleC13cmFwOndyYXA7IGdhcDo4cHg7IH0KICAubGlzdHMgYnV0dG9uIHsKICAgIGhlaWdodDozNnB4OyBib3JkZXItcmFkaXVzOjEwcHg7IHBhZGRpbmc6MCAxMnB4OyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OjYwMDsgZm9udC1zaXplOjEzcHg7IHRyYW5zZm9ybTpub25lOwogIH0KICAubGlzdHMgYnV0dG9uLm9uIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50LWRpbSk7IGNvbG9yOiB2YXIoLS1mZyk7IGJvcmRlci1jb2xvcjogY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1hY2NlbnQpIDQwJSwgdmFyKC0tYm9yZGVyKSk7IH0KICAuY2hpcCB7CiAgICAtLW1vZGU6IHZhcigtLWFjY2VudCk7CiAgICBtaW4taGVpZ2h0OiA4NnB4OyBib3JkZXItcmFkaXVzOiAxNHB4OyBwYWRkaW5nOiAxMnB4IDEzcHggMTFweDsgdGV4dC1hbGlnbjogbGVmdDsgY29sb3I6IHZhcigtLWZnKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tbW9kZSkgMjYlLCB2YXIoLS1ib3JkZXIpKTsKICAgIGJhY2tncm91bmQ6CiAgICAgIHJhZGlhbC1ncmFkaWVudCgxMjAlIDkwJSBhdCAxMDAlIDAlLCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLW1vZGUpIDE4JSwgdHJhbnNwYXJlbnQpLCB0cmFuc3BhcmVudCA1OCUpLAogICAgICBsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLW1vZGUpIDEwJSwgdmFyKC0tYmcpKSwgdmFyKC0tYmcpKTsKICAgIHRyYW5zaXRpb246IHRyYW5zZm9ybSAxNTBtcyB2YXIoLS1lYXNlKSwgYm9yZGVyLWNvbG9yIDE1MG1zIHZhcigtLWVhc2UpLCBib3gtc2hhZG93IDIwMG1zIHZhcigtLWVhc2UpOwogIH0KICAuY2hpcDpob3Zlcjpub3QoOmRpc2FibGVkKSB7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoLTJweCk7CiAgICBib3JkZXItY29sb3I6IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tbW9kZSkgNDglLCB2YXIoLS1ib3JkZXIpKTsKICAgIGJveC1zaGFkb3c6IDAgMTRweCAzMHB4IC0yMnB4IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tbW9kZSkgNzAlLCB0cmFuc3BhcmVudCk7CiAgfQogIC5jaGlwLm9uIHsKICAgIGJvcmRlci1jb2xvcjogY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1tb2RlKSA3MCUsIHRyYW5zcGFyZW50KTsKICAgIGJhY2tncm91bmQ6CiAgICAgIHJhZGlhbC1ncmFkaWVudCgxMjAlIDkwJSBhdCAxMDAlIDAlLCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLW1vZGUpIDI4JSwgdHJhbnNwYXJlbnQpLCB0cmFuc3BhcmVudCA1OCUpLAogICAgICBsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLW1vZGUpIDE4JSwgdmFyKC0tYmcpKSwgdmFyKC0tc3VyZikpOwogICAgYm94LXNoYWRvdzogMCAwIDAgMXB4IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tbW9kZSkgMjIlLCB0cmFuc3BhcmVudCksIDAgMTZweCAzMnB4IC0yMHB4IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tbW9kZSkgNTUlLCB0cmFuc3BhcmVudCk7CiAgfQogIC5jaGlwIC5sYWIgeyBmb250LXNpemU6IDIycHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGxldHRlci1zcGFjaW5nOiAtLjA0ZW07IGxpbmUtaGVpZ2h0OjE7IGNvbG9yOiB2YXIoLS1tb2RlKTsgfQogIC5jaGlwIC5oaW50IHsgbWFyZ2luLXRvcDo3cHg7IGZvbnQtc2l6ZToxMXB4OyBjb2xvcjogdmFyKC0tbXV0ZWQpOyB9CiAgLmNoaXAgLmNudCB7IG1hcmdpbi10b3A6NHB4OyBmb250LXNpemU6MTBweDsgbGV0dGVyLXNwYWNpbmc6LjA4ZW07IHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsgY29sb3I6IHZhcigtLXN1YnRsZSk7IH0KICAuc3RhdHMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdCg1LCBtaW5tYXgoMCwgMWZyKSk7IGdhcDogMTBweDsgfQogIC5zdGF0IHsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYmFja2dyb3VuZDogY29sb3ItbWl4KGluIG9rbGFiLCB2YXIoLS1iZykgNzAlLCB0cmFuc3BhcmVudCk7IGJvcmRlci1yYWRpdXM6IDEwcHg7IHBhZGRpbmc6IDEwcHggMTJweDsgfQogIC5zdGF0IGIgeyBmb250LXdlaWdodDogNjAwOyBmb250LXZhcmlhbnQtbnVtZXJpYzogdGFidWxhci1udW1zOyBmb250LXNpemU6IDE4cHg7IGRpc3BsYXk6YmxvY2s7IG1hcmdpbi10b3A6MnB4OyB9CiAgLmxvZyB7CiAgICBmb250LWZhbWlseTogIklCTSBQbGV4IE1vbm8iLCB1aS1tb25vc3BhY2UsIENvbnNvbGFzLCBtb25vc3BhY2U7IGZvbnQtc2l6ZTogMTNweDsKICAgIG1pbi1oZWlnaHQ6IDI4MHB4OyBtYXgtaGVpZ2h0OiA0MjBweDsgb3ZlcmZsb3c6IGF1dG87IHBhZGRpbmc6IDhweCAxNnB4OwogICAgY29udGFpbjogc3RyaWN0OwogICAgY29udGVudC12aXNpYmlsaXR5OiBhdXRvOwogIH0KICAubG9nIC5yb3cgewogICAgZGlzcGxheTpmbGV4OyBnYXA6MTJweDsgaGVpZ2h0OiAyMnB4OyBsaW5lLWhlaWdodDogMjJweDsgYWxpZ24taXRlbXM6Y2VudGVyOwogICAgYW5pbWF0aW9uOiBsb2cgLjE2cyB2YXIoLS1lYXNlKSBib3RoOyBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC5sb2cgLnJvdy5oaXQtb2sgeyBhbmltYXRpb246IGhpdGZsYXNoIC41cyB2YXIoLS1lYXNlKSBib3RoOyB9CiAgLmFuaW0tcGFnZSB7IGFuaW1hdGlvbjogcGFnZWluIC4zMnMgdmFyKC0tZWFzZSkgYm90aDsgfQogIC5sb2cgLnJvdyBzcGFuLm5hbWUgeyBmbGV4OjE7IG1pbi13aWR0aDowOyBvdmVyZmxvdzpoaWRkZW47IHRleHQtb3ZlcmZsb3c6ZWxsaXBzaXM7IHdoaXRlLXNwYWNlOm5vd3JhcDsgfQogIC5sb2cgLnJvdyBzcGFuLmxhYiB7IGNvbG9yOiB2YXIoLS1zdWJ0bGUpOyBmbGV4LXNocmluazowOyB9CiAgLm9rIHsgY29sb3I6IHZhcigtLWFjY2VudCk7IH0gLm5vIHsgY29sb3I6IHZhcigtLXRha2VuKTsgfSAuYmFkIHsgY29sb3I6IHZhcigtLXdhcm4pOyB9CiAgLmhpdCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTJweDsgcGFkZGluZzogMTJweCAxNnB4OyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZik7IGJvcmRlci1yYWRpdXM6IDEycHg7IG1hcmdpbi1ib3R0b206IDhweDsgYW5pbWF0aW9uOiByaXNlIC4zMnMgdmFyKC0tZWFzZSkgYm90aDsgd2lkdGg6MTAwJTsgdGV4dC1hbGlnbjpsZWZ0OyBjb2xvcjppbmhlcml0OyB9CiAgLmhpdDpob3ZlciB7IGJvcmRlci1jb2xvcjogdmFyKC0tYm9yZGVyLXN0cm9uZyk7IH0KICAubW9kIHsKICAgIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYmFja2dyb3VuZDogdmFyKC0tc3VyZik7IGJvcmRlci1yYWRpdXM6IDE2cHg7IHBhZGRpbmc6IDIwcHg7IHRleHQtYWxpZ246bGVmdDsgY29sb3I6aW5oZXJpdDsKICAgIHRyYW5zaXRpb246IHRyYW5zZm9ybSAyMDBtcyB2YXIoLS1lYXNlKSwgYm9yZGVyLWNvbG9yIDIwMG1zIHZhcigtLWVhc2UpLCBib3gtc2hhZG93IDIwMG1zIHZhcigtLWVhc2UpOwogIH0KICAubW9kOmhvdmVyIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC0zcHgpOyBib3JkZXItY29sb3I6IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSAzMiUsIHZhcigtLWJvcmRlcikpOwogICAgYm94LXNoYWRvdzogMCAwIDAgMXB4IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSAxMCUsIHRyYW5zcGFyZW50KSwgMCAyMnB4IDUwcHggLTI4cHggcmdiYSg0NiwyMjksMTU3LC4yOCk7IH0KICAubW9kcyB7IGRpc3BsYXk6Z3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyBnYXA6IDE0cHg7IH0KICAuaGlkZGVuIHsgZGlzcGxheTogbm9uZSAhaW1wb3J0YW50OyB9CiAgbGFiZWwubGFiIHsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi10b3A6IDEycHg7IH0KICAuaGludCB7IGNvbG9yOiB2YXIoLS1zdWJ0bGUpOyBmb250LXNpemU6IDEycHg7IG1hcmdpbi10b3A6IDEycHg7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogIGgxIHsgbWFyZ2luOiAycHggMCA0cHg7IGZvbnQtc2l6ZTogMjhweDsgbGV0dGVyLXNwYWNpbmc6IC0uMDNlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIGgyIHsgbWFyZ2luOiAwOyBsZXR0ZXItc3BhY2luZzogLS4wMmVtOyB9CiAgLm1pbnQgeyBoZWlnaHQ6IDFweDsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDkwZGVnLCB0cmFuc3BhcmVudCwgdmFyKC0tYWNjZW50KSwgdHJhbnNwYXJlbnQpOyBtYXJnaW46IDEycHggMCAwOyBtYXgtd2lkdGg6IDE4MHB4OyBhbmltYXRpb246IGJyZWF0aGUgMi44cyBlYXNlLWluLW91dCBpbmZpbml0ZTsgfQogIC5saXZlIHsgZGlzcGxheTppbmxpbmUtZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6NnB4OyBmb250LXNpemU6MTFweDsgZm9udC13ZWlnaHQ6NTAwOyBjb2xvcjogdmFyKC0tYWNjZW50KTsgfQogIC5kb3QgeyB3aWR0aDo2cHg7IGhlaWdodDo2cHg7IGJvcmRlci1yYWRpdXM6NTAlOyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBhbmltYXRpb246IHB1bHNlIDEuNnMgZWFzZS1pbi1vdXQgaW5maW5pdGU7IH0KICAuc2NhbiB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgb3ZlcmZsb3c6IGhpZGRlbjsgaGVpZ2h0OiA2cHg7IGJvcmRlci1yYWRpdXM6IDk5cHg7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgfQogIC5zY2FuIGkgeyBwb3NpdGlvbjphYnNvbHV0ZTsgaW5zZXQ6MCBhdXRvIDAgMDsgd2lkdGg6MzYlOyBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoOTBkZWcsIHRyYW5zcGFyZW50LCB2YXIoLS1hY2NlbnQpLCB0cmFuc3BhcmVudCk7IGFuaW1hdGlvbjogc2N4IDEuMzVzIGVhc2UtaW4tb3V0IGluZmluaXRlOyB9CiAgLnNwaW5uZXIgeyB3aWR0aDoxNnB4OyBoZWlnaHQ6MTZweDsgYm9yZGVyOjJweCBzb2xpZCBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudC1mZykgMjUlLCB0cmFuc3BhcmVudCk7IGJvcmRlci10b3AtY29sb3I6IGN1cnJlbnRDb2xvcjsgYm9yZGVyLXJhZGl1czo1MCU7IGFuaW1hdGlvbjogc3BpbiAuN3MgbGluZWFyIGluZmluaXRlOyBkaXNwbGF5OmlubGluZS1ibG9jazsgdmVydGljYWwtYWxpZ246bWlkZGxlOyBtYXJnaW4tcmlnaHQ6OHB4OyB9CiAgLm5hbWUtb2sgeyBjb2xvcjogdmFyKC0tYWNjZW50KTsgZm9udC1zaXplOiAxNHB4OyBhbmltYXRpb246IHJpc2UgLjRzIHZhcigtLWVhc2UpIGJvdGg7IH0KICAuc2hha2UgeyBhbmltYXRpb246IHNoYWtlIC4zMnMgdmFyKC0tZWFzZSk7IH0KICB0ZXh0YXJlYSB7IHBhZGRpbmc6IDEwcHggMTJweDsgcmVzaXplOiB2ZXJ0aWNhbDsgd2lkdGg6IDEwMCU7IH0KICAuZG90cyB7IGRpc3BsYXk6ZmxleDsgZ2FwOjZweDsgbWFyZ2luLXRvcDoxMnB4OyB9CiAgLmRvdHMgaSB7IGZsZXg6MTsgaGVpZ2h0OjZweDsgYm9yZGVyLXJhZGl1czo5OXB4OyBiYWNrZ3JvdW5kOiB2YXIoLS1ib3JkZXIpOyB9CiAgLmRvdHMgaS5vbiB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJveC1zaGFkb3c6IDAgMCAxMnB4IGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSA0NSUsIHRyYW5zcGFyZW50KTsgfQogIC5iYW5uZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQtZGltKTsgY29sb3I6IHZhcigtLWFjY2VudCk7IGZvbnQtc2l6ZToxMnB4OyB0ZXh0LWFsaWduOmNlbnRlcjsgcGFkZGluZzo4cHg7IGJvcmRlci1ib3R0b206MXB4IHNvbGlkIGNvbG9yLW1peChpbiBva2xhYiwgdmFyKC0tYWNjZW50KSAyMCUsIHRyYW5zcGFyZW50KTsgfQogIC5tb2RhbC1iYWNrIHsKICAgIHBvc2l0aW9uOmZpeGVkOyBpbnNldDowOyB6LWluZGV4OjgwOyBkaXNwbGF5OmdyaWQ7IHBsYWNlLWl0ZW1zOmNlbnRlcjsgcGFkZGluZzoyNHB4OwogICAgYmFja2dyb3VuZDogcmdiYSg1LDcsNiwuNzIpOyBiYWNrZHJvcC1maWx0ZXI6IGJsdXIoOHB4KTsgYW5pbWF0aW9uOiByaXNlIC4xOHMgdmFyKC0tZWFzZSkgYm90aDsKICB9CiAgLm1vZGFsLWNhcmQgeyB3aWR0aDogbWluKDQwMHB4LCAxMDAlKTsgcGFkZGluZzogMjRweDsgfQogIC5tb2RhbC1jYXJkIGgyIHsgZm9udC1zaXplOjE4cHg7IGZvbnQtd2VpZ2h0OjYwMDsgbGV0dGVyLXNwYWNpbmc6LS4wMmVtOyB9CiAgLm1vZGFsLWNhcmQgcCB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IG1hcmdpbjogOHB4IDAgMDsgZm9udC1zaXplOjE0cHg7IGxpbmUtaGVpZ2h0OjEuNTsgfQogIC5tb2RhbC1jYXJkIC5yb3cgeyBkaXNwbGF5OmZsZXg7IGp1c3RpZnktY29udGVudDpmbGV4LWVuZDsgZ2FwOjhweDsgbWFyZ2luLXRvcDoyMHB4OyB9CiAgQGtleWZyYW1lcyByaXNlIHsgZnJvbSB7IG9wYWNpdHk6MDsgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKDEwcHgpOyBmaWx0ZXI6IGJsdXIoNHB4KTt9IHRvIHsgb3BhY2l0eToxOyB0cmFuc2Zvcm06bm9uZTsgZmlsdGVyOm5vbmU7fSB9CiAgQGtleWZyYW1lcyBwdWxzZSB7IDAlLDEwMCV7b3BhY2l0eTouMzV9IDUwJXtvcGFjaXR5OjF9IH0KICBAa2V5ZnJhbWVzIHNjeCB7IGZyb20geyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTEyMCUpO30gdG8geyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMjIwJSk7fSB9CiAgQGtleWZyYW1lcyBzcGluIHsgdG8geyB0cmFuc2Zvcm06IHJvdGF0ZSgzNjBkZWcpO30gfQogIEBrZXlmcmFtZXMgc2hha2UgeyAwJSwxMDAle3RyYW5zZm9ybTpub25lfSAyMCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTZweCl9IDQwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWCg1cHgpfSA2MCV7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTNweCl9IDgwJXt0cmFuc2Zvcm06dHJhbnNsYXRlWCgycHgpfSB9CiAgQGtleWZyYW1lcyBsb2cgeyBmcm9tIHsgb3BhY2l0eTowOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTE0cHgpO30gdG8geyBvcGFjaXR5OjE7IHRyYW5zZm9ybTpub25lO30gfQogIEBrZXlmcmFtZXMgaGl0Zmxhc2ggewogICAgMCUgeyBiYWNrZ3JvdW5kOiBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLWFjY2VudCkgMjIlLCB0cmFuc3BhcmVudCk7IH0KICAgIDEwMCUgeyBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsgfQogIH0KICBAa2V5ZnJhbWVzIG5vZmxhc2ggewogICAgMCUgeyBiYWNrZ3JvdW5kOiBjb2xvci1taXgoaW4gb2tsYWIsIHZhcigtLXRha2VuKSAxNCUsIHRyYW5zcGFyZW50KTsgfQogICAgMTAwJSB7IGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OyB9CiAgfQogIEBrZXlmcmFtZXMgcGFnZWluIHsgZnJvbSB7IG9wYWNpdHk6MDsgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKDhweCk7fSB0byB7IG9wYWNpdHk6MTsgdHJhbnNmb3JtOm5vbmU7fSB9CiAgQGtleWZyYW1lcyBkcmlmdCB7IGZyb20geyBiYWNrZ3JvdW5kLXBvc2l0aW9uOiAwIDAsIDAgMDt9IHRvIHsgYmFja2dyb3VuZC1wb3NpdGlvbjogNTZweCA1NnB4LCA1NnB4IDU2cHg7fSB9CiAgQGtleWZyYW1lcyBicmVhdGhlIHsgMCUsMTAwJXtvcGFjaXR5Oi40NX0gNTAle29wYWNpdHk6MX0gfQogIEBrZXlmcmFtZXMgc2hlZW4geyB0byB7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCg0MjAlKTsgfSB9CiAgQG1lZGlhIChwcmVmZXJzLXJlZHVjZWQtbW90aW9uOiByZWR1Y2UpIHsKICAgICogeyBhbmltYXRpb246IG5vbmUgIWltcG9ydGFudDsgdHJhbnNpdGlvbjogbm9uZSAhaW1wb3J0YW50OyB9CiAgfQogIEBtZWRpYSAobWF4LXdpZHRoOiAxMTAwcHgpIHsKICAgIC5tb2RlcyB7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogcmVwZWF0KDIsIG1pbm1heCgwLDFmcikpOyB9CiAgICAubW9kcyB7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyOyB9CiAgfQo8L3N0eWxlPgoKPHNjcmlwdD4Kd2luZG93Ll9fb2ZkdEJyaWRnZSA9IHRydWU7CmNvbnN0IGJyaWRnZU5hbWVzID0gWwogICdvZmR0U3RhdGUnLCAnb2ZkdFNldHVwJywgJ29mZHRQcm9maWxlJywKICAnb2ZkdFN0YXJ0JywgJ29mZHRTdG9wJywgJ29mZHRDbGVhckhpdHMnLCAnb2ZkdENvcHknLAogICdvZmR0UGluZycsICdvZmR0VXBkYXRlJywgJ29mZHRSZWFkeScKXTsKYnJpZGdlTmFtZXMuZm9yRWFjaChmbiA9PiB7CiAgd2luZG93W2ZuXSA9IGFzeW5jIGZ1bmN0aW9uKGFyZykgewogICAgbGV0IHBheWxvYWQgPSB7fTsKICAgIGlmICh0eXBlb2YgYXJnID09PSAnc3RyaW5nJykgewogICAgICB0cnkgeyBwYXlsb2FkID0gSlNPTi5wYXJzZShhcmcpOyB9IGNhdGNoKGUpIHsgcGF5bG9hZCA9IHsgdGV4dDogYXJnIH07IH0KICAgIH0gZWxzZSBpZiAoYXJnKSB7CiAgICAgIHBheWxvYWQgPSBhcmc7CiAgICB9CiAgICB0cnkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgnL2FwaS8nICsgZm4sIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKQogICAgICB9KTsKICAgICAgcmV0dXJuIGF3YWl0IHJlcy50ZXh0KCk7CiAgICB9IGNhdGNoKGVycikgewogICAgICBjb25zb2xlLmVycm9yKCdBUEkgY2FsbCBmYWlsZWQ6JywgZm4sIGVycik7CiAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7IG9rOiBmYWxzZSwgZXJyb3I6IGVyci5tZXNzYWdlIH0pOwogICAgfQogIH07Cn0pOwoKLy8gU1NFIGZvciBzdHJlYW1pbmcgbG9ncy9zdGF0cyB0byBVSQp0cnkgewogIGNvbnN0IGV2dFNvdXJjZSA9IG5ldyBFdmVudFNvdXJjZSgnL2FwaS9ldmVudHMnKTsKICBldnRTb3VyY2Uub25tZXNzYWdlID0gZnVuY3Rpb24oZSkgewogICAgdHJ5IHsKICAgICAgY29uc3QgbXNnID0gSlNPTi5wYXJzZShlLmRhdGEpOwogICAgICBpZiAobXNnLnR5cGUgPT09ICdwdXNoJyAmJiB0eXBlb2Ygd2luZG93Ll9fb2ZkdFB1c2ggPT09ICdmdW5jdGlvbicpIHsKICAgICAgICB3aW5kb3cuX19vZmR0UHVzaChtc2cucGF5bG9hZCk7CiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdkb25lJyAmJiB0eXBlb2Ygd2luZG93Ll9fb2ZkdERvbmUgPT09ICdmdW5jdGlvbicpIHsKICAgICAgICB3aW5kb3cuX19vZmR0RG9uZSgpOwogICAgICB9CiAgICB9IGNhdGNoKGVycikge30KICB9Owp9IGNhdGNoKGUpIHt9Cjwvc2NyaXB0Pgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGNsYXNzPSJzaGVsbCI+CjxkaXYgY2xhc3M9InRiIiBpZD0idGl0bGViYXIiPgogIDxkaXYgY2xhc3M9ImJyYW5kIj4KICAgIDxzdmcgY2xhc3M9Im1hcmsiIHZpZXdCb3g9IjAgMCAzMiAzMiIgd2lkdGg9IjE2IiBoZWlnaHQ9IjE2IiBhcmlhLWhpZGRlbj0idHJ1ZSI+CiAgICAgIDxyZWN0IHg9IjEuMiIgeT0iMS4yIiB3aWR0aD0iMjkuNiIgaGVpZ2h0PSIyOS42IiByeD0iOCIgZmlsbD0iIzBiMGUwYyIgc3Ryb2tlPSIjMmVlNTlkIiBzdHJva2Utb3BhY2l0eT0iLjQ1IiBzdHJva2Utd2lkdGg9IjEuNCIvPgogICAgICA8cmVjdCB4PSI4IiB5PSI4IiB3aWR0aD0iMTYiIGhlaWdodD0iNiIgcng9IjIiIGZpbGw9IiNlZWYzZjAiLz4KICAgICAgPHJlY3QgeD0iOCIgeT0iMTgiIHdpZHRoPSIxNiIgaGVpZ2h0PSI2IiByeD0iMiIgZmlsbD0iIzJlZTU5ZCIvPgogICAgPC9zdmc+CiAgICA8Yj5PRjxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1hY2NlbnQpIj5EVDwvc3Bhbj48L2I+CiAgPC9kaXY+CiAgPGRpdiBjbGFzcz0id2luIiBpZD0id2luQnRucyI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9Im1pbkJ0biIgdGl0bGU9Ik1pbmltaXplIj7igJQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0ibWF4QnRuIiB0aXRsZT0iTWF4aW1pemUiPuKWoTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ4IiBpZD0iY2xvc2VCdG4iIHRpdGxlPSJDbG9zZSI+4pyVPC9idXR0b24+CiAgPC9kaXY+CjwvZGl2PgoKPGRpdiBpZD0ic2V0dXAiIGNsYXNzPSJzZXR1cCBoaWRkZW4iPgogIDxkaXYgY2xhc3M9Indhc2giPjwvZGl2PjxkaXYgY2xhc3M9ImdyaWRiZyI+PC9kaXY+CiAgPGRpdiBjbGFzcz0iZ2F0ZS1jYXJkIiBzdHlsZT0ibWF4LXdpZHRoOjQ4MHB4Ij4KICAgIDxkaXYgY2xhc3M9IndtIHNldHVwIj4KICAgICAgPGRpdiBjbGFzcz0id20tbmFtZSI+T0Y8c3Bhbj5EVDwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0id20tc3ViIj5DSEVDS0VSPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImtpY2tlciI+U2V0dXA8L2Rpdj4KICAgIDxkaXYgaWQ9InNldHVwU3RlcExhYiIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXN1YnRsZSk7bWFyZ2luLXRvcDo0cHgiPlN0ZXAgMSBvZiAzPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJkb3RzIiBpZD0ic2V0dXBEb3RzIj48aSBjbGFzcz0ib24iPjwvaT48aT48L2k+PGk+PC9pPjwvZGl2PgogICAgPGRpdiBjbGFzcz0icGFuZWwiIHN0eWxlPSJwYWRkaW5nOjI0cHg7bWFyZ2luLXRvcDoxNnB4Ij4KICAgICAgPGgyIGlkPSJzZXR1cFRpdGxlIiBzdHlsZT0iZm9udC1zaXplOjIycHgiPlJ1biBhIGNoZWNrPC9oMj4KICAgICAgPHAgaWQ9InNldHVwQm9keSIgc3R5bGU9ImNvbG9yOnZhcigtLW11dGVkKTttYXJnaW46MTJweCAwIDAiPlBpY2sgYSBwbGF0Zm9ybS4gUGljayBhIG1vZGUgbGlrZSA0TC4gSGl0IFN0YXJ0LiBBdmFpbGFibGUgbmFtZXMgbGFuZCBpbiBIaXRzLjwvcD4KICAgICAgPGRpdiBpZD0ic2V0dXBIb29rIiBjbGFzcz0iaGlkZGVuIiBzdHlsZT0ibWFyZ2luLXRvcDoxNnB4Ij4KICAgICAgICA8aW5wdXQgaWQ9InNldHVwV2ViaG9vayIgY2xhc3M9ImZpZWxkIiBwbGFjZWhvbGRlcj0iaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv4oCmIiAvPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7bWFyZ2luLXRvcDoyMHB4Ij4KICAgICAgICA8YnV0dG9uIGlkPSJzZXR1cEJhY2siIGNsYXNzPSJidG4gZ2hvc3QgaGlkZGVuIj5CYWNrPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBpZD0ic2V0dXBOZXh0IiBjbGFzcz0iYnRuIiBzdHlsZT0iZmxleDoxIj5Db250aW51ZTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGJ1dHRvbiBpZD0ic2V0dXBTa2lwIiBjbGFzcz0iYnRuIGdob3N0IiBzdHlsZT0id2lkdGg6MTAwJTttYXJnaW4tdG9wOjhweDtoZWlnaHQ6MzZweDtmb250LXNpemU6MTNweCI+U2tpcDwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPGRpdiBpZD0iYXBwIiBjbGFzcz0iYXBwIGhpZGRlbiI+CiAgPGRpdiBjbGFzcz0id2FzaCI+PC9kaXY+PGRpdiBjbGFzcz0iZ3JpZGJnIj48L2Rpdj4KICA8YXNpZGU+CiAgICA8ZGl2IGNsYXNzPSJ3bSBzaWRlIj4KICAgICAgPGRpdiBjbGFzcz0id20tbmFtZSI+T0Y8c3Bhbj5EVDwvc3Bhbj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0id20tc3ViIj5DSEVDS0VSPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgc3R5bGU9Im1hcmdpbjowIDE2cHggOHB4O3BhZGRpbmc6MTBweCAxMnB4IiBjbGFzcz0icGFuZWwiPgogICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyIj4KICAgICAgICA8c3BhbiBjbGFzcz0ia2lja2VyIj5FbmdpbmU8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9ImxpdmUiPjxzcGFuIGNsYXNzPSJkb3QiPjwvc3Bhbj5MaXZlPC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0icGxhbkNoaXAiIHN0eWxlPSJtYXJnaW4tdG9wOjRweDtjb2xvcjp2YXIoLS1hY2NlbnQpO2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MTRweCI+c25pcGVycjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ3aG8iPgogICAgICA8ZGl2IGlkPSJwZnBXcmFwIiBjbGFzcz0icGgiIHRpdGxlPSJDaGFuZ2UgcGhvdG8iPj88L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8ZGl2IGlkPSJ3aG9OYW1lIiBzdHlsZT0iZm9udC13ZWlnaHQ6NjAwIj7igJQ8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxpbnB1dCBpZD0icGZwRmlsZSIgdHlwZT0iZmlsZSIgYWNjZXB0PSJpbWFnZS8qIiBjbGFzcz0iaGlkZGVuIiAvPgogICAgPGRpdiBjbGFzcz0ia2lja2VyIiBzdHlsZT0icGFkZGluZzo4cHggMjBweCA0cHgiPlBsYXRmb3JtczwvZGl2PgogICAgPG5hdiBpZD0ibmF2UGxhdCI+PC9uYXY+CiAgICA8ZGl2IGNsYXNzPSJraWNrZXIiIHN0eWxlPSJwYWRkaW5nOjE0cHggMjBweCA0cHgiPldvcmtzcGFjZTwvZGl2PgogICAgPG5hdj4KICAgICAgPGJ1dHRvbiBkYXRhLXZpZXc9ImRhc2giPk1vZHVsZXM8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBkYXRhLXZpZXc9ImNoZWNrZXIiIGNsYXNzPSJvbiI+Q2hlY2tlcjwvYnV0dG9uPgogICAgICA8YnV0dG9uIGRhdGEtdmlldz0iaGl0cyI+SGl0czwvYnV0dG9uPgogICAgICA8YnV0dG9uIGRhdGEtdmlldz0ic2V0dGluZ3MiPlNldHRpbmdzPC9idXR0b24+CiAgICA8L25hdj4KICAgIDxkaXYgc3R5bGU9Im1hcmdpbi10b3A6YXV0bztwYWRkaW5nOjEycHgiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIHN0eWxlPSJ3aWR0aDoxMDAlO2hlaWdodDozNnB4O2ZvbnQtc2l6ZToxM3B4IiBpZD0ibG9nb3V0Ij5SZWxvYWQ8L2J1dHRvbj4KICAgICAgPGRpdiBjbGFzcz0ia2lja2VyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7bWFyZ2luLXRvcDo4cHgiPnY0LjM8L2Rpdj4KICAgIDwvZGl2PgogIDwvYXNpZGU+CiAgPG1haW4+CiAgICA8ZGl2IGlkPSJ1cGRCYW5uZXIiIGNsYXNzPSJiYW5uZXIgaGlkZGVuIj48L2Rpdj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWRhc2giIGNsYXNzPSJoaWRkZW4iPgogICAgICA8cCBjbGFzcz0ia2lja2VyIj5Nb2R1bGVzPC9wPgogICAgICA8aDEgaWQ9ImRhc2hIaSI+UGljayBhIHBsYXRmb3JtPC9oMT4KICAgICAgPGRpdiBjbGFzcz0ibWludCI+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZHMiIGlkPSJkYXNoTW9kcyIgc3R5bGU9Im1hcmdpbi10b3A6MjJweCI+PC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgICA8c2VjdGlvbiBpZD0idmlldy1jaGVja2VyIj4KICAgICAgPHAgY2xhc3M9ImtpY2tlciIgaWQ9InBsYXRUYWciPkRpc2NvcmQ8L3A+CiAgICAgIDxoMSBpZD0icGxhdFRpdGxlIj5EaXNjb3JkIGNoZWNrZXI8L2gxPgogICAgICA8ZGl2IGNsYXNzPSJtaW50Ij48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icGFuZWwiIHN0eWxlPSJwYWRkaW5nOjIwcHg7bWFyZ2luLXRvcDoyMHB4Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJraWNrZXIiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjEwcHgiPk1vZGU8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJtb2RlcyIgaWQ9Im1vZGVzIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJsaXN0Qm94IiBjbGFzcz0iaGlkZGVuIiBzdHlsZT0ibWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgICAgIDx0ZXh0YXJlYSBpZD0ibGlzdCIgcm93cz0iNSIgcGxhY2Vob2xkZXI9Im9uZSBuYW1lIHBlciBsaW5lIj48L3RleHRhcmVhPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9IndvcmRCb3giIGNsYXNzPSJoaWRkZW4iIHN0eWxlPSJtYXJnaW4tdG9wOjE0cHgiPgogICAgICAgICAgPGRpdiBjbGFzcz0ia2lja2VyIiBzdHlsZT0ibWFyZ2luLWJvdHRvbTo4cHgiPldvcmRsaXN0PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJsaXN0cyIgaWQ9IndvcmRsaXN0cyI+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7bWFyZ2luLXRvcDoxNnB4O2FsaWduLWl0ZW1zOmNlbnRlcjtmbGV4LXdyYXA6d3JhcCI+CiAgICAgICAgICA8YnV0dG9uIGlkPSJzdGFydCIgY2xhc3M9ImJ0biBsZyI+U3RhcnQ8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gaWQ9InN0b3AiIGNsYXNzPSJidG4gZ2hvc3QgaGlkZGVuIj5TdG9wPC9idXR0b24+CiAgICAgICAgICA8YnV0dG9uIGlkPSJyZXNldCIgY2xhc3M9ImJ0biBnaG9zdCI+UmVzZXQ8L2J1dHRvbj4KICAgICAgICAgIDxsYWJlbCBpZD0ibG9vcExhYiIgc3R5bGU9Im1hcmdpbi1sZWZ0OmF1dG87Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtc2l6ZToxNHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjA7dXNlci1zZWxlY3Q6bm9uZTstd2Via2l0LXVzZXItc2VsZWN0Om5vbmU7b3V0bGluZTpub25lIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJpbmYiIC8+IExvb3A8L2xhYmVsPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icGFuZWwiIHN0eWxlPSJwYWRkaW5nOjIwcHg7bWFyZ2luLXRvcDoxNHB4Ij4KICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbTo4cHgiPgogICAgICAgICAgPHNwYW4gY2xhc3M9ImtpY2tlciI+UHJvZ3Jlc3M8L3NwYW4+CiAgICAgICAgICA8c3BhbiBjbGFzcz0ia2lja2VyIiBpZD0icnVuU3RhdGUiPlJlYWR5PC9zcGFuPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InNjYW4iIGlkPSJzY2FuIj48aSBjbGFzcz0iaGlkZGVuIiBpZD0ic2NhbkkiPjwvaT48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0cyIgc3R5bGU9Im1hcmdpbi10b3A6MTRweCI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48ZGl2IGNsYXNzPSJraWNrZXIiPkNoZWNrZWQ8L2Rpdj48YiBpZD0icy1jaGVja2VkIj4wPC9iPjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ia2lja2VyIj5BdmFpbGFibGU8L2Rpdj48YiBpZD0icy1hdmFpbCIgY2xhc3M9Im9rIj4wPC9iPjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ia2lja2VyIj5UYWtlbjwvZGl2PjxiIGlkPSJzLXRha2VuIj4wPC9iPjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ia2lja2VyIj5Vbmtub3duPC9kaXY+PGIgaWQ9InMtZXJyIj4wPC9iPjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGRpdiBjbGFzcz0ia2lja2VyIj5TYXZlZDwvZGl2PjxiIGlkPSJzLWhpdHMiPjA8L2I+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbCBsb2ciIGlkPSJsb2ciIHN0eWxlPSJtYXJnaW4tdG9wOjE0cHgiPldhaXRpbmc8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpdHMiIGNsYXNzPSJoaWRkZW4iPgogICAgICA8cCBjbGFzcz0ia2lja2VyIj5IaXRzPC9wPgogICAgICA8aDE+QXZhaWxhYmxlIG5hbWVzPC9oMT4KICAgICAgPGRpdiBjbGFzcz0ibWludCI+PC9kaXY+CiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O21hcmdpbjoxOHB4IDAgMTZweCI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IiBpZD0iY29weUhpdHMiPkNvcHk8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJjbGVhckhpdHMiPkNsZWFyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGlkPSJoaXRMaXN0Ij48L2Rpdj4KICAgIDwvc2VjdGlvbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXNldHRpbmdzIiBjbGFzcz0iaGlkZGVuIj4KICAgICAgPHAgY2xhc3M9ImtpY2tlciI+U2V0dGluZ3M8L3A+CiAgICAgIDxoMT5TZXR0aW5nczwvaDE+CiAgICAgIDxkaXYgY2xhc3M9Im1pbnQiPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbCIgc3R5bGU9InBhZGRpbmc6MjBweDttYXJnaW4tdG9wOjIwcHgiPgogICAgICAgIDxkaXYgY2xhc3M9ImtpY2tlciI+SWRlbnRpdHk8L2Rpdj4KICAgICAgICA8aDIgc3R5bGU9ImZvbnQtc2l6ZToxOHB4O21hcmdpbjo0cHggMCAxMnB4Ij5Vc2VybmFtZTwvaDI+CiAgICAgICAgPGxhYmVsIGNsYXNzPSJsYWIiIHN0eWxlPSJtYXJnaW4tdG9wOjAiPjxzcGFuIGNsYXNzPSJraWNrZXIiPkRpc3BsYXkgbmFtZTwvc3Bhbj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImF0Ij48c3Bhbj5APC9zcGFuPjxpbnB1dCBpZD0ic2V0VXNlciIgcGxhY2Vob2xkZXI9Im5ldyB1c2VybmFtZSIgLz48L2Rpdj48L2xhYmVsPgogICAgICAgIDxsYWJlbCBjbGFzcz0ibGFiIj48c3BhbiBjbGFzcz0ia2lja2VyIj5QaG90bzwvc3Bhbj4KICAgICAgICAgIDxkaXYgc3R5bGU9Im1hcmdpbi10b3A6OHB4Ij48YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJzZXRQZnAiPkNob29zZSBwaG90bzwvYnV0dG9uPjwvZGl2PjwvbGFiZWw+CiAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDttYXJnaW4tdG9wOjE2cHgiPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0ic2F2ZVByb2YiPlNhdmU8L2J1dHRvbj4KICAgICAgICAgIDxwIGlkPSJzZXRNc2ciIGNsYXNzPSJoaW50IiBzdHlsZT0idGV4dC1hbGlnbjpsZWZ0O21hcmdpbjowIj48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbCIgc3R5bGU9InBhZGRpbmc6MjBweDttYXJnaW4tdG9wOjE0cHgiPgogICAgICAgIDxkaXYgY2xhc3M9ImtpY2tlciI+TmV0d29yazwvZGl2PgogICAgICAgIDxoMiBzdHlsZT0iZm9udC1zaXplOjE4cHg7bWFyZ2luOjRweCAwIDEycHgiPlByb3hpZXM8L2gyPgogICAgICAgIDx0ZXh0YXJlYSBpZD0ic2V0UHJveGllcyIgcm93cz0iNiIgcGxhY2Vob2xkZXI9ImlwOnBvcnQmIzEwO3VzZXI6cGFzc0BpcDpwb3J0Ij48L3RleHRhcmVhPgogICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEycHg7bWFyZ2luLXRvcDoxMnB4Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9InNhdmVQcm94aWVzIj5TYXZlIHByb3hpZXM8L2J1dHRvbj4KICAgICAgICAgIDxzcGFuIGNsYXNzPSJoaW50IiBzdHlsZT0ibWFyZ2luOjA7dGV4dC1hbGlnbjpsZWZ0IiBpZD0ic2V0UHJveHlNc2ciPjwvc3Bhbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InBhbmVsIiBzdHlsZT0icGFkZGluZzoyMHB4O21hcmdpbi10b3A6MTRweCI+CiAgICAgICAgPGRpdiBjbGFzcz0ia2lja2VyIj5Qb3dlcjwvZGl2PgogICAgICAgIDxoMiBzdHlsZT0iZm9udC1zaXplOjE4cHg7bWFyZ2luOjRweCAwIDEycHgiPldvcmtlcnM8L2gyPgogICAgICAgIDxkaXYgY2xhc3M9Imxpc3RzIiBpZD0icG93ZXJCdG5zIj48L2Rpdj4KICAgICAgICA8bGFiZWwgY2xhc3M9ImxhYiI+PHNwYW4gY2xhc3M9ImtpY2tlciI+Q3VzdG9tPC9zcGFuPgogICAgICAgICAgPGlucHV0IGlkPSJzZXRXb3JrZXJzIiBjbGFzcz0iZmllbGQiIHR5cGU9Im51bWJlciIgbWluPSIxIiBtYXg9IjUwMCIgc3RlcD0iMSIgLz48L2xhYmVsPgogICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEycHg7bWFyZ2luLXRvcDoxMnB4Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9InNhdmVQb3dlciIgdHlwZT0iYnV0dG9uIj5TYXZlIHBvd2VyPC9idXR0b24+CiAgICAgICAgICA8c3BhbiBjbGFzcz0iaGludCIgc3R5bGU9Im1hcmdpbjowO3RleHQtYWxpZ246bGVmdCIgaWQ9InNldFBvd2VyTXNnIj48L3NwYW4+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbCIgc3R5bGU9InBhZGRpbmc6MjBweDttYXJnaW4tdG9wOjE0cHgiPgogICAgICAgIDxkaXYgY2xhc3M9ImtpY2tlciI+QWxlcnRzPC9kaXY+CiAgICAgICAgPGgyIHN0eWxlPSJmb250LXNpemU6MThweDttYXJnaW46NHB4IDAgMTJweCI+V2ViaG9vazwvaDI+CiAgICAgICAgPGlucHV0IGlkPSJzZXRXZWJob29rIiBjbGFzcz0iZmllbGQiIHBsYWNlaG9sZGVyPSJodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcy/igKYiIC8+CiAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDttYXJnaW4tdG9wOjEycHgiPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGdob3N0IiBpZD0ic2F2ZUhvb2siPlNhdmUgd2ViaG9vazwvYnV0dG9uPgogICAgICAgICAgPHNwYW4gY2xhc3M9ImhpbnQiIHN0eWxlPSJtYXJnaW46MDt0ZXh0LWFsaWduOmxlZnQiIGlkPSJzZXRIb29rTXNnIj48L3NwYW4+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbCIgc3R5bGU9InBhZGRpbmc6MjBweDttYXJnaW4tdG9wOjE0cHgiPgogICAgICAgIDxoMiBzdHlsZT0iZm9udC1zaXplOjE4cHgiPlNldHVwIGd1aWRlPC9oMj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gZ2hvc3QiIGlkPSJvcGVuR3VpZGUiIHN0eWxlPSJtYXJnaW4tdG9wOjEycHgiPk9wZW4gZ3VpZGU8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgPC9tYWluPgo8L2Rpdj4KPC9kaXY+Cgo8ZGl2IGlkPSJtb2RhbCIgY2xhc3M9ImhpZGRlbiI+CiAgPGRpdiBjbGFzcz0ibW9kYWwtYmFjayIgaWQ9Im1vZGFsQmFjayI+CiAgICA8ZGl2IGNsYXNzPSJwYW5lbCBtb2RhbC1jYXJkIj4KICAgICAgPGgyIGlkPSJtb2RhbFRpdGxlIj5BcmUgeW91IHN1cmU/PC9oMj4KICAgICAgPHAgaWQ9Im1vZGFsQm9keSI+PC9wPgogICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBnaG9zdCIgaWQ9Im1vZGFsQ2FuY2VsIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJtb2RhbE9rIj5PSzwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KPHNjcmlwdD4KZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY29udGV4dG1lbnUnLCBlID0+IGUucHJldmVudERlZmF1bHQoKSk7CmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ3NlbGVjdHN0YXJ0JywgZSA9PiB7CiAgY29uc3QgdCA9IGUudGFyZ2V0OwogIGlmICh0ICYmICh0LmNsb3Nlc3QoJ2lucHV0LCB0ZXh0YXJlYScpKSkgcmV0dXJuOwogIGUucHJldmVudERlZmF1bHQoKTsKfSk7CmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCBlID0+IHsKICBpZiAoKGUuY3RybEtleSB8fCBlLm1ldGFLZXkpICYmIChlLmtleSA9PT0gJ2EnIHx8IGUua2V5ID09PSAnQScpKSB7CiAgICBjb25zdCB0ID0gZS50YXJnZXQ7CiAgICBpZiAodCAmJiAodC50YWdOYW1lID09PSAnSU5QVVQnIHx8IHQudGFnTmFtZSA9PT0gJ1RFWFRBUkVBJykpIHJldHVybjsKICAgIGUucHJldmVudERlZmF1bHQoKTsKICB9Cn0pOwpyZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCkgPT4gcmVxdWVzdEFuaW1hdGlvbkZyYW1lKCgpID0+IHsKICB0cnkgeyB3aW5kb3cub2ZkdFJlYWR5KCk7IH0gY2F0Y2ggKGUpIHt9Cn0pKTsKZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIGUgPT4gewogIGlmIChlLmtleSA9PT0gJ0YxMicgfHwgKGUuY3RybEtleSAmJiBlLnNoaWZ0S2V5ICYmIChlLmtleSA9PT0gJ0knIHx8IGUua2V5ID09PSAnSicgfHwgZS5rZXkgPT09ICdDJykpKSB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgfQp9KTsKCmFzeW5jIGZ1bmN0aW9uIGFwaShuYW1lLCBib2R5KSB7CiAgY29uc3QgZm4gPSB3aW5kb3dbbmFtZV07CiAgaWYgKHR5cGVvZiBmbiAhPT0gJ2Z1bmN0aW9uJykgdGhyb3cgbmV3IEVycm9yKCdtaXNzaW5nJyk7CiAgY29uc3QgcmF3ID0gYXdhaXQgZm4oSlNPTi5zdHJpbmdpZnkoYm9keSB8fCB7fSkpOwogIHJldHVybiB0eXBlb2YgcmF3ID09PSAnc3RyaW5nJyA/IEpTT04ucGFyc2UocmF3KSA6IHJhdzsKfQoKY29uc3QgUExBVFMgPSBbCiAge2lkOidkaXNjb3JkJywgbmFtZTonRGlzY29yZCcsIGJsdXJiOidVbmlxdWUgdXNlcm5hbWVzLid9LAogIHtpZDonZ3VucycsIG5hbWU6J0d1bnMubG9sJywgYmx1cmI6J1Byb2ZpbGUgbmFtZXMuJywgZG93bjp0cnVlfSwKICB7aWQ6J21lZGFsJywgbmFtZTonTWVkYWwudHYnLCBibHVyYjonQ3JlYXRvciBuYW1lcy4nLCBkb3duOnRydWV9LApdOwpjb25zdCBNT0RFUyA9IFsKICB7aWQ6JzRsJywgbGFiZWw6JzRMJywgaGludDonRm91ciBsZXR0ZXJzJywgY291bnQ6JzQ1Niw5NzYnLCB0b25lOicjMmVlNTlkJ30sCiAge2lkOiczbCcsIGxhYmVsOiczTCcsIGhpbnQ6J1RocmVlIGxldHRlcnMnLCBjb3VudDonMTcsNTc2JywgdG9uZTonIzVhZDRlOCd9LAogIHtpZDonNGMnLCBsYWJlbDonNEMnLCBoaW50OidMZXR0ZXJzICsgMC05IC4gXycsIGNvdW50OicyLjBNKycsIHRvbmU6JyM3ZWUwYTgnfSwKICB7aWQ6JzNjJywgbGFiZWw6JzNDJywgaGludDonTGV0dGVycyArIDAtOSAuIF8nLCBjb3VudDonNTQsODcyJywgdG9uZTonIzRmZDRjOCd9LAogIHtpZDond29yZHMnLCBsYWJlbDonV29yZHMnLCBoaW50OidFbmdsaXNoIGRpY3Rpb25hcnknLCBjb3VudDonMzAsMTkwJywgdG9uZTonI2E4ZTBjNCd9LAogIHtpZDonbGlzdCcsIGxhYmVsOidMaXN0JywgaGludDonWW91ciBuYW1lcycsIGNvdW50Oid5b3VycycsIHRvbmU6JyM5YWEzOWQnfSwKICB7aWQ6JzNuJywgbGFiZWw6JzNOJywgaGludDonMDAw4oCTOTk5JywgY291bnQ6JzEsMDAwJywgdG9uZTonI2Q3YjU2YSd9LAogIHtpZDonNG4nLCBsYWJlbDonNE4nLCBoaW50OicwMDAw4oCTOTk5OScsIGNvdW50OicxMCwwMDAnLCB0b25lOicjZTBjMDdhJ30sCiAge2lkOic1bicsIGxhYmVsOic1TicsIGhpbnQ6J0ZpdmUgZGlnaXRzJywgY291bnQ6JzEwMCwwMDAnLCB0b25lOicjYzlhMzVhJ30sCiAge2lkOidzZW1pJywgbGFiZWw6J1NlbWknLCBoaW50OidfeCAgLnggIF9feHgnLCBjb3VudDonOTI0LDQ4MCcsIHRvbmU6JyM3MGM4YTgnfSwKXTsKY29uc3QgU0VUVVAgPSBbCiAge3RpdGxlOidSdW4gYSBjaGVjaycsIGJvZHk6J1BpY2sgYSBwbGF0Zm9ybS4gUGljayBhIG1vZGUgbGlrZSA0TC4gSGl0IFN0YXJ0LiBBdmFpbGFibGUgbmFtZXMgbGFuZCBpbiBIaXRzLid9LAogIHt0aXRsZTonV2ViaG9vaycsIGJvZHk6J1Bhc3RlIGEgRGlzY29yZCB3ZWJob29rIGlmIHlvdSB3YW50IGhpdHMgaW4gRGlzY29yZC4gTGVhdmUgaXQgYmxhbmsgaWYgeW91IG9ubHkgd2FudCB0aGUgbGl2ZSBsb2cuJywgaG9vazp0cnVlfSwKICB7dGl0bGU6J1Byb3hpZXMgKyBwcm9maWxlJywgYm9keTonUGFzdGUgcHJveGllcyBpbiBTZXR0aW5ncy4gQ2hhbmdlIHRoZSBsb2NhbCBkaXNwbGF5IG5hbWUgaW4gU2V0dGluZ3MuIEF2YWlsYWJsZSBuYW1lcyBhcmUgc2F2ZWQgbG9jYWxseSBpbiBIaXRzLid9LApdOwpsZXQgc3RhdGUgPSB7dXNlcm5hbWU6J3NuaXBlcnInLCBwZnA6JycsIGhpdHM6W10sIHZlcnNpb246JzQuMycsIHByb3hpZXM6JycsIHdlYmhvb2s6JycsIHNldHVwRG9uZTp0cnVlLCB3b3JkbGlzdDonZW5nbGlzaCcsIHdvcmtlcnM6MjUwfTsKbGV0IHdvcmRsaXN0ID0gJ2VuZ2xpc2gnOwpjb25zdCBXT1JETElTVFMgPSBbCiAge2lkOidlbmdsaXNoJywgbGFiZWw6J0VuZ2xpc2ggMzBrJywgY291bnQ6JzMwLDE5MCd9LAogIHtpZDonc2hvcnQnLCBsYWJlbDonU2hvcnQnLCBjb3VudDonNjU1J30sCl07CmxldCBwbGF0Zm9ybSA9ICdkaXNjb3JkJywgbW9kZSA9ICc0bCcsIHJ1bm5pbmcgPSBmYWxzZTsKbGV0IHN0YXRzID0ge2NoZWNrZWQ6MCwgYXZhaWxhYmxlOjAsIHRha2VuOjAsIGVycm9yczowfTsKbGV0IHJ1blNlcSA9IDA7CmxldCBsYXN0UnVuTW9kZSA9ICc0bCc7CmxldCBsYXN0UnVuSW5mID0gZmFsc2U7CmxldCBydW5TdG9wcGVkID0gZmFsc2U7CmxldCBtYXhpbWl6ZWQgPSBmYWxzZTsKbGV0IHNldHVwU3RlcCA9IDA7CmxldCB2aWV3ID0gJ2NoZWNrZXInOwoKZnVuY3Rpb24gJChpZCl7IHJldHVybiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7IH0KZnVuY3Rpb24gcGxhdERvd24oaWQpewogIGNvbnN0IHAgPSBQTEFUUy5maW5kKHggPT4geC5pZD09PWlkKTsKICByZXR1cm4gISEocCAmJiBwLmRvd24pOwp9CmZ1bmN0aW9uIG5vdGljZURvd24oKXsKICByZXR1cm4gYXNrKCdOb3QgYXZhaWxhYmxlIGluIHRoaXMgYnVpbGQnLCAnVGhpcyBwYWNrYWdlIHVzZXMgdGhlIFNuaXBlcnIgY2hlY2tlciBlbmdpbmUuJywgJ09LJywgZmFsc2UsIHRydWUpOwp9CmZ1bmN0aW9uIHNob3dFcnIodCl7CiAgY29uc3QgZT0kKCdlcnInKTsgaWYgKCFlKSByZXR1cm47IGUudGV4dENvbnRlbnQ9dDsgZS5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nLCAhdCk7CiAgaWYgKHQpIHsgZS5jbGFzc0xpc3QucmVtb3ZlKCdzaGFrZScpOyB2b2lkIGUub2Zmc2V0V2lkdGg7IGUuY2xhc3NMaXN0LmFkZCgnc2hha2UnKTsgfQp9CmZ1bmN0aW9uIHByb3h5TGluZXModGV4dCl7CiAgcmV0dXJuICh0ZXh0fHwnJykuc3BsaXQoL1xyP1xuLykubWFwKHM9PnMudHJpbSgpKS5maWx0ZXIocz0+cyAmJiAhcy5zdGFydHNXaXRoKCcjJykpLmxlbmd0aDsKfQpmdW5jdGlvbiBzdGF0dXNMYWJlbChzdCl7CiAgaWYgKHN0PT09J2F2YWlsYWJsZScpIHJldHVybiAnYXZhaWxhYmxlJzsKICBpZiAoc3Q9PT0ndGFrZW4nKSByZXR1cm4gJ3Rha2VuJzsKICBpZiAoc3Q9PT0naW52YWxpZCcpIHJldHVybiAnaW52YWxpZCc7CiAgaWYgKHN0PT09J2NsYWltZWQnKSByZXR1cm4gJ2NsYWltZWQnOwogIHJldHVybiAndW5rbm93bic7Cn0KZnVuY3Rpb24gcGFpbnRQbGFuKCl7CiAgaWYgKCQoJ3BsYW5DaGlwJykpICQoJ3BsYW5DaGlwJykudGV4dENvbnRlbnQgPSAnc25pcGVycic7Cn0KbGV0IHBpbmdUaW1lciA9IDA7CmxldCBwaW5nQnVzeSA9IGZhbHNlOwpmdW5jdGlvbiBzdGFydExpdmUoKXsKICBzdG9wTGl2ZSgpOwogIHBhaW50UGxhbigpOwogIHBpbmdUaW1lciA9IHNldEludGVydmFsKGxpdmVQaW5nLCAzMDAwKTsKICBsaXZlUGluZygpOwogIGlmICghd2luZG93Ll91cGRUaW1lcikgewogICAgd2luZG93Ll91cGRUaW1lciA9IHNldEludGVydmFsKGNoZWNrVXBkYXRlLCA2MDAwMCk7CiAgICBjaGVja1VwZGF0ZSgpOwogIH0KfQpmdW5jdGlvbiBzdG9wTGl2ZSgpewogIGlmIChwaW5nVGltZXIpIHsgY2xlYXJJbnRlcnZhbChwaW5nVGltZXIpOyBwaW5nVGltZXIgPSAwOyB9Cn0KYXN5bmMgZnVuY3Rpb24gbGl2ZVBpbmcoKXsKICBpZiAocGluZ0J1c3kpIHJldHVybjsKICBwaW5nQnVzeSA9IHRydWU7CiAgdHJ5IHsKICAgIGNvbnN0IGogPSBhd2FpdCBhcGkoJ29mZHRQaW5nJywge30pOwogICAgaWYgKGogJiYgai5vayAmJiBqLnN0YXRlKSB7CiAgICAgIGNvbnN0IHByZXYgPSBzdGF0ZS51c2VybmFtZTsKICAgICAgc3RhdGUgPSBPYmplY3QuYXNzaWduKHN0YXRlLCBqLnN0YXRlKTsKICAgICAgaWYgKHN0YXRlLnVzZXJuYW1lICE9PSBwcmV2KSByZW5kZXJXaG8oKTsKICAgIH0KICB9IGNhdGNoKGUpIHt9CiAgZmluYWxseSB7IHBpbmdCdXN5ID0gZmFsc2U7IH0KfQoKY29uc3QgdGl0bGViYXIgPSAkKCd0aXRsZWJhcicpOwppZiAodGl0bGViYXIpIHsKdGl0bGViYXIuYWRkRXZlbnRMaXN0ZW5lcignbW91c2Vkb3duJywgKGUpID0+IHsKICBpZiAoZS5idXR0b24gIT09IDApIHJldHVybjsKICBpZiAoZS50YXJnZXQuY2xvc2VzdCgnI3dpbkJ0bnMnKSkgcmV0dXJuOwogIGUucHJldmVudERlZmF1bHQoKTsKICB0cnkgeyB3aW5kb3cub2ZkdERyYWcoKTsgfSBjYXRjaCAoZXJyKSB7fQp9KTsKdGl0bGViYXIuYWRkRXZlbnRMaXN0ZW5lcignZGJsY2xpY2snLCAoZSkgPT4gewogIGlmIChlLnRhcmdldC5jbG9zZXN0KCcjd2luQnRucycpKSByZXR1cm47CiAgZG9NYXgoKTsKfSk7Cn0KZnVuY3Rpb24gZG9NYXgoKXsKICB0cnkgewogICAgY29uc3QgciA9IHdpbmRvdy5vZmR0TWF4KCk7CiAgICBQcm9taXNlLnJlc29sdmUocikudGhlbigodikgPT4gewogICAgICBtYXhpbWl6ZWQgPSAhIXY7CiAgICAgICQoJ21heEJ0bicpLnRleHRDb250ZW50ID0gbWF4aW1pemVkID8gJ+KdkCcgOiAn4pahJzsKICAgICAgJCgnbWF4QnRuJykudGl0bGUgPSBtYXhpbWl6ZWQgPyAnUmVzdG9yZScgOiAnTWF4aW1pemUnOwogICAgfSk7CiAgfSBjYXRjaCAoZXJyKSB7fQp9CiQoJ21pbkJ0bicpLm9uY2xpY2sgPSAoZSkgPT4geyBlLnN0b3BQcm9wYWdhdGlvbigpOyB0cnkgeyB3aW5kb3cub2ZkdE1pbigpOyB9IGNhdGNoKGVycikge30gfTsKJCgnbWF4QnRuJykub25jbGljayA9IChlKSA9PiB7IGUuc3RvcFByb3BhZ2F0aW9uKCk7IGRvTWF4KCk7IH07CiQoJ2Nsb3NlQnRuJykub25jbGljayA9IChlKSA9PiB7CiAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICBpZiAod2luZG93Ll9fb2ZkdEFza0Nsb3NlKSB3aW5kb3cuX19vZmR0QXNrQ2xvc2UoKTsKfTsKCmxldCBjbG9zZUFza0J1c3kgPSBmYWxzZTsKd2luZG93Ll9fb2ZkdEFza0Nsb3NlID0gYXN5bmMgZnVuY3Rpb24oKXsKICBpZiAoY2xvc2VBc2tCdXN5KSByZXR1cm47CiAgY2xvc2VBc2tCdXN5ID0gdHJ1ZTsKICB0cnkgewogICAgY29uc3QgYm9keSA9IHJ1bm5pbmcgPyAnQSBjaGVjayBpcyBzdGlsbCBydW5uaW5nLicgOiAnWW91IGNhbiBvcGVuIGl0IGFnYWluIGFueSB0aW1lLic7CiAgICBjb25zdCBvayA9IGF3YWl0IGFzaygnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGNsb3NlIHRoaXM/JywgYm9keSwgJ0Nsb3NlJywgdHJ1ZSk7CiAgICBpZiAoIW9rKSByZXR1cm47CiAgICBzdG9wUnVuKCk7CiAgICBhd2FpdCBmbHVzaFNldHRpbmdzKCk7CiAgICB0cnkgeyB3aW5kb3cub2ZkdFF1aXQoKTsgfSBjYXRjaChlcnIpIHt9CiAgfSBmaW5hbGx5IHsKICAgIGNsb3NlQXNrQnVzeSA9IGZhbHNlOwogIH0KfTsKCmZ1bmN0aW9uIGFzayh0aXRsZSwgYm9keSwgb2tMYWJlbCwgZGFuZ2VyLCBoaWRlQ2FuY2VsLCBjYW5jZWxMYWJlbCl7CiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAkKCdtb2RhbFRpdGxlJykudGV4dENvbnRlbnQgPSB0aXRsZTsKICAgICQoJ21vZGFsQm9keScpLnRleHRDb250ZW50ID0gYm9keSB8fCAnJzsKICAgICQoJ21vZGFsT2snKS50ZXh0Q29udGVudCA9IG9rTGFiZWwgfHwgJ09LJzsKICAgICQoJ21vZGFsT2snKS5zdHlsZS5iYWNrZ3JvdW5kID0gZGFuZ2VyID8gJ3ZhcigtLWRhbmdlciknIDogJ3ZhcigtLWFjY2VudCknOwogICAgJCgnbW9kYWxPaycpLnN0eWxlLmNvbG9yID0gZGFuZ2VyID8gJyNmZmYnIDogJ3ZhcigtLWFjY2VudC1mZyknOwogICAgJCgnbW9kYWxDYW5jZWwnKS50ZXh0Q29udGVudCA9IGNhbmNlbExhYmVsIHx8IChkYW5nZXIgPyAnU3RheScgOiAnQ2FuY2VsJyk7CiAgICAkKCdtb2RhbENhbmNlbCcpLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICEhaGlkZUNhbmNlbCk7CiAgICAkKCdtb2RhbCcpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgY29uc3Qgb25LZXkgPSAoZXYpID0+IHsKICAgICAgaWYgKGV2LmtleSA9PT0gJ0VzY2FwZScpIHsgZXYucHJldmVudERlZmF1bHQoKTsgZG9uZShoaWRlQ2FuY2VsID8gdHJ1ZSA6IGZhbHNlKTsgfQogICAgICBlbHNlIGlmIChldi5rZXkgPT09ICdFbnRlcicgJiYgIWRhbmdlcikgeyBldi5wcmV2ZW50RGVmYXVsdCgpOyBkb25lKHRydWUpOyB9CiAgICB9OwogICAgY29uc3QgZG9uZSA9ICh2KSA9PiB7CiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdrZXlkb3duJywgb25LZXkpOwogICAgICAkKCdtb2RhbCcpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgICAkKCdtb2RhbENhbmNlbCcpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICAkKCdtb2RhbE9rJykub25jbGljayA9IG51bGw7CiAgICAgICQoJ21vZGFsQ2FuY2VsJykub25jbGljayA9IG51bGw7CiAgICAgICQoJ21vZGFsQmFjaycpLm9uY2xpY2sgPSBudWxsOwogICAgICByZXNvbHZlKHYpOwogICAgfTsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgb25LZXkpOwogICAgJCgnbW9kYWxPaycpLm9uY2xpY2sgPSAoZXYpID0+IHsgZXYuc3RvcFByb3BhZ2F0aW9uKCk7IGRvbmUodHJ1ZSk7IH07CiAgICAkKCdtb2RhbENhbmNlbCcpLm9uY2xpY2sgPSAoZXYpID0+IHsgZXYuc3RvcFByb3BhZ2F0aW9uKCk7IGRvbmUoZmFsc2UpOyB9OwogICAgJCgnbW9kYWxCYWNrJykub25jbGljayA9IChldikgPT4geyBpZiAoZXYudGFyZ2V0ID09PSAkKCdtb2RhbEJhY2snKSkgZG9uZShoaWRlQ2FuY2VsID8gdHJ1ZSA6IGZhbHNlKTsgfTsKICAgIHNldFRpbWVvdXQoKCkgPT4geyB0cnkgeyAoaGlkZUNhbmNlbCA/ICQoJ21vZGFsT2snKSA6ICQoJ21vZGFsQ2FuY2VsJykpLmZvY3VzKCk7IH0gY2F0Y2goZXJyKSB7fSB9LCAwKTsKICB9KTsKfQoKZnVuY3Rpb24gc2hvd1NldHVwKG9uKXsKICAkKCdzZXR1cCcpLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICFvbik7CiAgJCgnYXBwJykuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgb24pOwogIGlmIChvbikgcGFpbnRTZXR1cCgpOwp9CmZ1bmN0aW9uIHBhaW50U2V0dXAoKXsKICBjb25zdCBzID0gU0VUVVBbc2V0dXBTdGVwXTsKICAkKCdzZXR1cFRpdGxlJykudGV4dENvbnRlbnQgPSBzLnRpdGxlOwogICQoJ3NldHVwQm9keScpLnRleHRDb250ZW50ID0gcy5ib2R5OwogICQoJ3NldHVwU3RlcExhYicpLnRleHRDb250ZW50ID0gJ1N0ZXAgJysoc2V0dXBTdGVwKzEpKycgb2YgJytTRVRVUC5sZW5ndGg7CiAgJCgnc2V0dXBIb29rJykuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgIXMuaG9vayk7CiAgJCgnc2V0dXBCYWNrJykuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgc2V0dXBTdGVwPT09MCk7CiAgJCgnc2V0dXBOZXh0JykudGV4dENvbnRlbnQgPSBzZXR1cFN0ZXA9PT1TRVRVUC5sZW5ndGgtMSA/ICdPcGVuIE9GRFQnIDogJ0NvbnRpbnVlJzsKICBbLi4uJCgnc2V0dXBEb3RzJykuY2hpbGRyZW5dLmZvckVhY2goKGVsLGkpID0+IGVsLmNsYXNzTGlzdC50b2dnbGUoJ29uJywgaTw9c2V0dXBTdGVwKSk7Cn0KJCgnc2V0dXBCYWNrJykub25jbGljayA9ICgpID0+IHsgaWYgKHNldHVwU3RlcD4wKSB7IHNldHVwU3RlcC0tOyBwYWludFNldHVwKCk7IH0gfTsKJCgnc2V0dXBOZXh0Jykub25jbGljayA9IGFzeW5jICgpID0+IHsKICBpZiAoU0VUVVBbc2V0dXBTdGVwXS5ob29rKSBzdGF0ZS53ZWJob29rID0gJCgnc2V0dXBXZWJob29rJykudmFsdWUudHJpbSgpOwogIGlmIChzZXR1cFN0ZXAgPCBTRVRVUC5sZW5ndGgtMSkgeyBzZXR1cFN0ZXArKzsgcGFpbnRTZXR1cCgpOyByZXR1cm47IH0KICBhd2FpdCBmaW5pc2hTZXR1cCgpOwp9OwokKCdzZXR1cFNraXAnKS5vbmNsaWNrID0gKCkgPT4gewogIGlmIChTRVRVUFtzZXR1cFN0ZXBdLmhvb2spIHN0YXRlLndlYmhvb2sgPSAkKCdzZXR1cFdlYmhvb2snKS52YWx1ZS50cmltKCk7CiAgZmluaXNoU2V0dXAoKTsKfTsKYXN5bmMgZnVuY3Rpb24gZmluaXNoU2V0dXAoKXsKICB0cnkgewogICAgaWYgKHN0YXRlLndlYmhvb2spIGF3YWl0IGFwaSgnb2ZkdFByb2ZpbGUnLCB7IHdlYmhvb2s6IHN0YXRlLndlYmhvb2sgfSk7CiAgICBhd2FpdCBhcGkoJ29mZHRTZXR1cCcsIHt9KTsKICB9IGNhdGNoKGUpIHt9CiAgc3RhdGUuc2V0dXBEb25lID0gdHJ1ZTsKICBzaG93U2V0dXAoZmFsc2UpOwogICQoJ2FwcCcpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwp9CgpmdW5jdGlvbiBlbnRlcihzKXsKICBzdGF0ZSA9IE9iamVjdC5hc3NpZ24oe3VzZXJuYW1lOidzbmlwZXJyJywgcGZwOicnLCBoaXRzOltdLCBwcm94aWVzOicnLCB3ZWJob29rOicnLCBzZXR1cERvbmU6dHJ1ZSwgd29yZGxpc3Q6J2VuZ2xpc2gnLCB3b3JrZXJzOjI1MH0sIHMgfHwgc3RhdGUpOwogIHdvcmRsaXN0ID0gc3RhdGUud29yZGxpc3QgPT09ICdzaG9ydCcgPyAnc2hvcnQnIDogJ2VuZ2xpc2gnOwogIHN0YXRlLndvcmtlcnMgPSBjbGFtcFdvcmtlcnMoc3RhdGUud29ya2Vycyk7CiAgJCgnc2V0UHJveGllcycpLnZhbHVlID0gc3RhdGUucHJveGllcyB8fCAnJzsKICAkKCdzZXRXZWJob29rJykudmFsdWUgPSBzdGF0ZS53ZWJob29rIHx8ICcnOwogICQoJ3NldHVwV2ViaG9vaycpLnZhbHVlID0gc3RhdGUud2ViaG9vayB8fCAnJzsKICBwYWludFBvd2VyKCk7CiAgcmVuZGVyV2hvKCk7CiAgcmVuZGVyTmF2KCk7CiAgcmVuZGVyTW9kZXMoKTsKICByZW5kZXJIaXRzKCk7CiAgcmVuZGVyRGFzaCgpOwogIGlmICghc3RhdGUuc2V0dXBEb25lKSB7CiAgICBzZXR1cFN0ZXAgPSAwOwogICAgc2hvd1NldHVwKHRydWUpOwogIH0gZWxzZSB7CiAgICAkKCdzZXR1cCcpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgJCgnYXBwJykuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAgfQogIGNoZWNrVXBkYXRlKCk7CiAgc3RhcnRMaXZlKCk7Cn0KZnVuY3Rpb24gcmVuZGVyV2hvKCl7CiAgJCgnd2hvTmFtZScpLnRleHRDb250ZW50ID0gc3RhdGUudXNlcm5hbWUgPyAnQCcrc3RhdGUudXNlcm5hbWUucmVwbGFjZSgvXkArLywnJykgOiAn4oCUJzsKICBwYWludFBsYW4oKTsKICAkKCdzZXRVc2VyJykudmFsdWUgPSAoc3RhdGUudXNlcm5hbWV8fCcnKS5yZXBsYWNlKC9eQCsvLCAnJyk7CiAgJCgnZGFzaEhpJykudGV4dENvbnRlbnQgPSBzdGF0ZS51c2VybmFtZSA/ICdXZWxjb21lIGJhY2ssICcrc3RhdGUudXNlcm5hbWUgOiAnUGljayBhIHBsYXRmb3JtJzsKICBjb25zdCB3cmFwID0gJCgncGZwV3JhcCcpOwogIGlmICghd3JhcCkgcmV0dXJuOwogIGlmIChzdGF0ZS5wZnApIHsKICAgIHdyYXAuY2xhc3NOYW1lID0gJyc7CiAgICB3cmFwLmlubmVySFRNTCA9ICcnOwogICAgY29uc3QgaW1nID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaW1nJyk7CiAgICBpbWcuc3JjID0gc3RhdGUucGZwOwogICAgaW1nLnN0eWxlLmNzc1RleHQgPSAnd2lkdGg6NDBweDtoZWlnaHQ6NDBweDtib3JkZXItcmFkaXVzOjUwJTtvYmplY3QtZml0OmNvdmVyO2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6YmxvY2snOwogICAgaW1nLm9uY2xpY2sgPSAoKSA9PiAkKCdwZnBGaWxlJykuY2xpY2soKTsKICAgIHdyYXAuYXBwZW5kQ2hpbGQoaW1nKTsKICB9IGVsc2UgewogICAgd3JhcC5jbGFzc05hbWUgPSAncGgnOwogICAgd3JhcC5pbm5lckhUTUwgPSAnJzsKICAgIHdyYXAudGV4dENvbnRlbnQgPSAoc3RhdGUudXNlcm5hbWV8fCc/JylbMF0udG9VcHBlckNhc2UoKTsKICAgIHdyYXAub25jbGljayA9ICgpID0+ICQoJ3BmcEZpbGUnKS5jbGljaygpOwogIH0KICAkKCdzLWhpdHMnKS50ZXh0Q29udGVudCA9IChzdGF0ZS5oaXRzfHxbXSkubGVuZ3RoOwp9CmZ1bmN0aW9uIHJlbmRlck5hdigpewogIGlmICghUExBVFMuc29tZShwID0+IHAuaWQ9PT1wbGF0Zm9ybSkgfHwgcGxhdERvd24ocGxhdGZvcm0pKSBwbGF0Zm9ybSA9ICdkaXNjb3JkJzsKICBjb25zdCBib3ggPSAkKCduYXZQbGF0Jyk7CiAgYm94LmlubmVySFRNTCA9ICcnOwogIFBMQVRTLmZvckVhY2gocCA9PiB7CiAgICBjb25zdCBiID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYnV0dG9uJyk7CiAgICBiLnRleHRDb250ZW50ID0gcC5uYW1lOwogICAgYi5jbGFzc05hbWUgPSAocC5pZD09PXBsYXRmb3JtID8gJ29uJyA6ICcnKSArIChwLmRvd24gPyAnIHNvb24nIDogJycpOwogICAgaWYgKHAuZG93bikgewogICAgICBjb25zdCB0YWcgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyk7CiAgICAgIHRhZy5jbGFzc05hbWUgPSAnc29vbi10YWcnOwogICAgICB0YWcudGV4dENvbnRlbnQgPSAnc29vbic7CiAgICAgIGIuYXBwZW5kQ2hpbGQodGFnKTsKICAgIH0KICAgIGIub25jbGljayA9ICgpID0+IHsKICAgICAgaWYgKHAuZG93bikgeyBub3RpY2VEb3duKCk7IHJldHVybjsgfQogICAgICBpZiAocnVubmluZykgewogICAgICAgIGFzaygnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIHN3aXRjaCBwbGF0Zm9ybXM/JywgJ0EgY2hlY2sgaXMgc3RpbGwgcnVubmluZy4gU3RvcCBpdCBhbmQgc3dpdGNoPycsICdTd2l0Y2gnLCB0cnVlKS50aGVuKChvaykgPT4gewogICAgICAgICAgaWYgKCFvaykgcmV0dXJuOwogICAgICAgICAgc3RvcFJ1bigpOyBlbmRSdW4oKTsKICAgICAgICAgIHBsYXRmb3JtID0gcC5pZDsgcmVuZGVyTmF2KCk7CiAgICAgICAgICAkKCdwbGF0VGFnJykudGV4dENvbnRlbnQgPSBwLm5hbWU7CiAgICAgICAgICAkKCdwbGF0VGl0bGUnKS50ZXh0Q29udGVudCA9IHAubmFtZSsnIGNoZWNrZXInOwogICAgICAgICAgc2V0VmlldygnY2hlY2tlcicpOwogICAgICAgIH0pOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwbGF0Zm9ybSA9IHAuaWQ7IHJlbmRlck5hdigpOwogICAgICAkKCdwbGF0VGFnJykudGV4dENvbnRlbnQgPSBwLm5hbWU7CiAgICAgICQoJ3BsYXRUaXRsZScpLnRleHRDb250ZW50ID0gcC5uYW1lKycgY2hlY2tlcic7CiAgICAgIHNldFZpZXcoJ2NoZWNrZXInKTsKICAgIH07CiAgICBib3guYXBwZW5kQ2hpbGQoYik7CiAgfSk7Cn0KZnVuY3Rpb24gcmVuZGVyTW9kZXMoKXsKICBjb25zdCBib3ggPSAkKCdtb2RlcycpOyBib3guaW5uZXJIVE1MPScnOwogIE1PREVTLmZvckVhY2goKG0sIGkpID0+IHsKICAgIGNvbnN0IGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGIuY2xhc3NOYW1lID0gJ2NoaXAnKyhtLmlkPT09bW9kZT8nIG9uJzonJyk7CiAgICBiLmRpc2FibGVkID0gcnVubmluZzsKICAgIGIuc3R5bGUuc2V0UHJvcGVydHkoJy0tbW9kZScsIG0udG9uZSk7CiAgICBiLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJsYWIiPjwvZGl2PjxkaXYgY2xhc3M9ImhpbnQiPjwvZGl2PjxkaXYgY2xhc3M9ImNudCI+PC9kaXY+JzsKICAgIGIucXVlcnlTZWxlY3RvcignLmxhYicpLnRleHRDb250ZW50ID0gbS5sYWJlbDsKICAgIGIucXVlcnlTZWxlY3RvcignLmhpbnQnKS50ZXh0Q29udGVudCA9IG0uaGludDsKICAgIGIucXVlcnlTZWxlY3RvcignLmNudCcpLnRleHRDb250ZW50ID0gbS5jb3VudDsKICAgIGIuc3R5bGUuYW5pbWF0aW9uRGVsYXkgPSAoaSo0MCkrJ21zJzsKICAgIGIub25jbGljayA9ICgpID0+IHsgaWYgKHJ1bm5pbmcpIHJldHVybjsgbW9kZT1tLmlkOyAkKCdsaXN0Qm94JykuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZGVuJywgbW9kZSE9PSdsaXN0Jyk7ICQoJ3dvcmRCb3gnKS5jbGFzc0xpc3QudG9nZ2xlKCdoaWRkZW4nLCBtb2RlIT09J3dvcmRzJyk7IHJlbmRlck1vZGVzKCk7IH07CiAgICBib3guYXBwZW5kQ2hpbGQoYik7CiAgfSk7CiAgY29uc3QgbGlzdHMgPSAkKCd3b3JkbGlzdHMnKTsKICBpZiAobGlzdHMpIHsKICAgIGxpc3RzLmlubmVySFRNTCA9ICcnOwogICAgV09SRExJU1RTLmZvckVhY2godyA9PiB7CiAgICAgIGNvbnN0IGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgICAgYi50eXBlID0gJ2J1dHRvbic7CiAgICAgIGIuY2xhc3NOYW1lID0gdy5pZD09PXdvcmRsaXN0ID8gJ29uJyA6ICcnOwogICAgICBiLmRpc2FibGVkID0gcnVubmluZzsKICAgICAgYi50ZXh0Q29udGVudCA9IHcubGFiZWwrJyDCtyAnK3cuY291bnQ7CiAgICAgIGIub25jbGljayA9ICgpID0+IHsKICAgICAgICBpZiAocnVubmluZykgcmV0dXJuOwogICAgICAgIHdvcmRsaXN0ID0gdy5pZDsKICAgICAgICBzdGF0ZS53b3JkbGlzdCA9IHcuaWQ7CiAgICAgICAgcmVuZGVyTW9kZXMoKTsKICAgICAgICB0cnkgeyBhcGkoJ29mZHRQcm9maWxlJywgeyB3b3JkbGlzdDogd29yZGxpc3QgfSk7IH0gY2F0Y2goZSkge30KICAgICAgfTsKICAgICAgbGlzdHMuYXBwZW5kQ2hpbGQoYik7CiAgICB9KTsKICB9Cn0KZnVuY3Rpb24gcmVuZGVyRGFzaCgpewogIGNvbnN0IGJveCA9ICQoJ2Rhc2hNb2RzJyk7IGJveC5pbm5lckhUTUw9Jyc7CiAgUExBVFMuZm9yRWFjaCgocCwgaSkgPT4gewogICAgY29uc3QgbiA9IChzdGF0ZS5oaXRzfHxbXSkuZmlsdGVyKGggPT4gaC5wbGF0Zm9ybT09PXAuaWQpLmxlbmd0aDsKICAgIGNvbnN0IGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGIuY2xhc3NOYW1lID0gJ21vZCc7CiAgICBiLnN0eWxlLmFuaW1hdGlvbkRlbGF5ID0gKGkqNzApKydtcyc7CiAgICBjb25zdCBjdGEgPSBwLmRvd24gPyAnU29vbicgOiAnT3BlbiBjaGVja2VyJzsKICAgIGIuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9ImtpY2tlciI+JytwLm5hbWUrJzwvZGl2PjxoMiBzdHlsZT0ibWFyZ2luLXRvcDo4cHg7Zm9udC1zaXplOjIwcHgiPicrcC5uYW1lKyc8L2gyPjxwIHN0eWxlPSJjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luOjZweCAwIDAiPicrcC5ibHVyYisnPC9wPjxkaXYgc3R5bGU9Im1hcmdpbi10b3A6MTZweDtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tc3VidGxlKSI+PHNwYW4+JytuKycgc2F2ZWQ8L3NwYW4+PHNwYW4gY2xhc3M9Im9rIj4nK2N0YSsnPC9zcGFuPjwvZGl2Pic7CiAgICBiLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIGlmIChwLmRvd24pIHsgbm90aWNlRG93bigpOyByZXR1cm47IH0KICAgICAgY29uc3QgZ28gPSAoKSA9PiB7CiAgICAgICAgcGxhdGZvcm0gPSBwLmlkOyByZW5kZXJOYXYoKTsKICAgICAgICAkKCdwbGF0VGFnJykudGV4dENvbnRlbnQgPSBwLm5hbWU7CiAgICAgICAgJCgncGxhdFRpdGxlJykudGV4dENvbnRlbnQgPSBwLm5hbWUrJyBjaGVja2VyJzsKICAgICAgICBzZXRWaWV3KCdjaGVja2VyJyk7CiAgICAgIH07CiAgICAgIGlmIChydW5uaW5nKSB7CiAgICAgICAgYXNrKCdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gc3dpdGNoIHBsYXRmb3Jtcz8nLCAnQSBjaGVjayBpcyBzdGlsbCBydW5uaW5nLiBTdG9wIGl0IGFuZCBzd2l0Y2g/JywgJ1N3aXRjaCcsIHRydWUpLnRoZW4oKG9rKSA9PiB7CiAgICAgICAgICBpZiAoIW9rKSByZXR1cm47CiAgICAgICAgICBzdG9wUnVuKCk7IGVuZFJ1bigpOyBnbygpOwogICAgICAgIH0pOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBnbygpOwogICAgfTsKICAgIGJveC5hcHBlbmRDaGlsZChiKTsKICB9KTsKfQpmdW5jdGlvbiBzZXRWaWV3KHYpewogIHZpZXcgPSB2OwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ1tkYXRhLXZpZXddJykuZm9yRWFjaCh4ID0+IHguY2xhc3NMaXN0LnRvZ2dsZSgnb24nLCB4LmRhdGFzZXQudmlldz09PXYpKTsKICBbJ2Rhc2gnLCdjaGVja2VyJywnaGl0cycsJ3NldHRpbmdzJ10uZm9yRWFjaChpZCA9PiB7CiAgICBjb25zdCBlbCA9ICQoJ3ZpZXctJytpZCk7CiAgICBjb25zdCBvbiA9IGlkPT09djsKICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsICFvbik7CiAgICBpZiAob24pIHsKICAgICAgZWwuY2xhc3NMaXN0LnJlbW92ZSgnYW5pbS1wYWdlJyk7CiAgICAgIHZvaWQgZWwub2Zmc2V0V2lkdGg7CiAgICAgIGVsLmNsYXNzTGlzdC5hZGQoJ2FuaW0tcGFnZScpOwogICAgfQogIH0pOwogIGlmICh2PT09J2hpdHMnKSByZW5kZXJIaXRzKCk7CiAgaWYgKHY9PT0nZGFzaCcpIHJlbmRlckRhc2goKTsKfQpkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdbZGF0YS12aWV3XScpLmZvckVhY2goYiA9PiBiLm9uY2xpY2sgPSAoKSA9PiBzZXRWaWV3KGIuZGF0YXNldC52aWV3KSk7CgokKCdwZnBGaWxlJykub25jaGFuZ2UgPSAoKSA9PiByZWFkUGZwKCQoJ3BmcEZpbGUnKS5maWxlc1swXSk7CiQoJ3NldFBmcCcpLm9uY2xpY2sgPSAoKSA9PiAkKCdwZnBGaWxlJykuY2xpY2soKTsKZnVuY3Rpb24gcmVhZFBmcChmaWxlKXsKICBpZiAoIWZpbGUpIHJldHVybjsKICBjb25zdCBpbWcgPSBuZXcgSW1hZ2UoKTsKICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGZpbGUpOwogIGltZy5vbmxvYWQgPSAoKSA9PiB7CiAgICBjb25zdCBjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnY2FudmFzJyk7CiAgICBjLndpZHRoID0gMTYwOyBjLmhlaWdodCA9IDE2MDsKICAgIGMuZ2V0Q29udGV4dCgnMmQnKS5kcmF3SW1hZ2UoaW1nLDAsMCwxNjAsMTYwKTsKICAgIHN0YXRlLnBmcCA9IGMudG9EYXRhVVJMKCdpbWFnZS9qcGVnJywgMC44NSk7CiAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICByZW5kZXJXaG8oKTsKICAgIGFwaSgnb2ZkdFByb2ZpbGUnLCB7IHBmcDogc3RhdGUucGZwIH0pLmNhdGNoKCgpID0+IHt9KTsKICB9OwogIGltZy5zcmMgPSB1cmw7Cn0KJCgnc2F2ZVByb2YnKS5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogIGNvbnN0IG5leHQgPSAkKCdzZXRVc2VyJykudmFsdWUucmVwbGFjZSgvXkArLywgJycpLnRyaW0oKTsKICBjb25zdCBjdXIgPSAoc3RhdGUudXNlcm5hbWV8fCcnKS5yZXBsYWNlKC9eQCsvLCAnJyk7CiAgaWYgKG5leHQgJiYgbmV4dC50b0xvd2VyQ2FzZSgpICE9PSBjdXIudG9Mb3dlckNhc2UoKSkgewogICAgaWYgKCEvXlthLXpBLVowLTldezMsMjB9JC8udGVzdChuZXh0KSkgewogICAgICAkKCdzZXRNc2cnKS50ZXh0Q29udGVudCA9ICdVc2UgMysgbGV0dGVycyBvciBudW1iZXJzLiBObyBzcGFjZXMsIF8gb3IgLic7CiAgICAgIHJldHVybjsKICAgIH0KICAgIGNvbnN0IG9rID0gYXdhaXQgYXNrKCdDaGFuZ2UgZGlzcGxheSBuYW1lPycsICdUaGUgbG9jYWwgcHJvZmlsZSBuYW1lIHdpbGwgYmVjb21lIEAnK25leHQrJy4nLCAnQ2hhbmdlJyk7CiAgICBpZiAoIW9rKSByZXR1cm47CiAgfQogIGNvbnN0IGJ0biA9ICQoJ3NhdmVQcm9mJyk7CiAgY29uc3QgbXNnID0gJCgnc2V0TXNnJyk7CiAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICBidG4uaW5uZXJIVE1MID0gJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+U2F2aW5nJzsKICBtc2cudGV4dENvbnRlbnQgPSAnJzsKICB0cnkgewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCdvZmR0UHJvZmlsZScsIHsgdXNlcm5hbWU6ICQoJ3NldFVzZXInKS52YWx1ZS5yZXBsYWNlKC9eQCsvLCAnJyksIHBmcDogc3RhdGUucGZwIHx8ICcnIH0pOwogICAgaWYgKHJlcy5vaykgewogICAgICBzdGF0ZSA9IE9iamVjdC5hc3NpZ24oc3RhdGUsIHJlcy5zdGF0ZSk7IHJlbmRlcldobygpOwogICAgICBtc2cuY2xhc3NOYW1lID0gJ25hbWUtb2snOwogICAgICBtc2cudGV4dENvbnRlbnQgPSAnU2F2ZWQnOwogICAgICBidG4udGV4dENvbnRlbnQgPSAnU2F2ZWQnOwogICAgICBzZXRUaW1lb3V0KCgpID0+IHsgYnRuLnRleHRDb250ZW50ID0gJ1NhdmUnOyBtc2cudGV4dENvbnRlbnQ9Jyc7IG1zZy5jbGFzc05hbWU9J2hpbnQnOyB9LCAxNjAwKTsKICAgIH0gZWxzZSB7CiAgICAgIG1zZy5jbGFzc05hbWUgPSAnZXJyJzsKICAgICAgbXNnLnRleHRDb250ZW50ID0gcmVzLmVycm9yIHx8ICdDb3VsZCBub3Qgc2F2ZSc7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICdTYXZlJzsKICAgIH0KICB9IGNhdGNoKGUpIHsKICAgIG1zZy5jbGFzc05hbWUgPSAnZXJyJzsKICAgIG1zZy50ZXh0Q29udGVudCA9ICdDb3VsZCBub3Qgc2F2ZSc7CiAgICBidG4udGV4dENvbnRlbnQgPSAnU2F2ZSc7CiAgfSBmaW5hbGx5IHsgYnRuLmRpc2FibGVkID0gZmFsc2U7IH0KfTsKJCgnc2F2ZVByb3hpZXMnKS5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogIGNvbnN0IHRleHQgPSAkKCdzZXRQcm94aWVzJykudmFsdWU7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgnb2ZkdFByb2ZpbGUnLCB7IHByb3hpZXM6IHRleHQgfSk7CiAgICBpZiAocmVzLm9rKSB7CiAgICAgIHN0YXRlID0gT2JqZWN0LmFzc2lnbihzdGF0ZSwgcmVzLnN0YXRlKTsKICAgICAgc3RhdGUucHJveGllcyA9IHRleHQ7CiAgICB9CiAgICBjb25zdCBuID0gcHJveHlMaW5lcyh0ZXh0KTsKICAgICQoJ3NldFByb3h5TXNnJykudGV4dENvbnRlbnQgPSBuID8gbisnIHNhdmVkJyA6ICdDbGVhcmVkJzsKICB9IGNhdGNoKGUpIHsgJCgnc2V0UHJveHlNc2cnKS50ZXh0Q29udGVudCA9ICdDb3VsZCBub3Qgc2F2ZSc7IH0KfTsKZnVuY3Rpb24gY2xhbXBXb3JrZXJzKG4pewogIG4gPSBwYXJzZUludChuLCAxMCk7CiAgaWYgKCFuIHx8IG4gPCAxKSByZXR1cm4gMjUwOwogIGlmIChuID4gNTAwKSByZXR1cm4gNTAwOwogIHJldHVybiBuOwp9CmZ1bmN0aW9uIHBhaW50UG93ZXIoKXsKICBjb25zdCBuID0gY2xhbXBXb3JrZXJzKHN0YXRlLndvcmtlcnMpOwogIHN0YXRlLndvcmtlcnMgPSBuOwogIGNvbnN0IGJveCA9ICQoJ3Bvd2VyQnRucycpOwogIGlmICghYm94KSByZXR1cm47CiAgYm94LmlubmVySFRNTCA9ICcnOwogIFsxMDAsMjAwLDI1MCw0MDAsNTAwXS5mb3JFYWNoKHAgPT4gewogICAgY29uc3QgYiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgYi50eXBlID0gJ2J1dHRvbic7CiAgICBiLnRleHRDb250ZW50ID0gcCsnIHBvd2VyJzsKICAgIGIuY2xhc3NOYW1lID0gbj09PXAgPyAnb24nIDogJyc7CiAgICBiLm9uY2xpY2sgPSAoKSA9PiB7IHZvaWQgc2F2ZVdvcmtlcnMocCk7IH07CiAgICBib3guYXBwZW5kQ2hpbGQoYik7CiAgfSk7CiAgY29uc3QgaW5wID0gJCgnc2V0V29ya2VycycpOwogIGlmIChpbnAgJiYgZG9jdW1lbnQuYWN0aXZlRWxlbWVudCAhPT0gaW5wKSBpbnAudmFsdWUgPSBTdHJpbmcobik7Cn0KYXN5bmMgZnVuY3Rpb24gc2F2ZVdvcmtlcnMobil7CiAgbiA9IGNsYW1wV29ya2VycyhuKTsKICBzdGF0ZS53b3JrZXJzID0gbjsKICBwYWludFBvd2VyKCk7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgnb2ZkdFByb2ZpbGUnLCB7IHdvcmtlcnM6IG4gfSk7CiAgICBpZiAocmVzICYmIHJlcy5vaykgc3RhdGUgPSBPYmplY3QuYXNzaWduKHN0YXRlLCByZXMuc3RhdGV8fHt9KTsKICAgIHN0YXRlLndvcmtlcnMgPSBuOwogIH0gY2F0Y2goZSkge30KICBjb25zdCBtc2cgPSAkKCdzZXRQb3dlck1zZycpOwogIGlmIChtc2cpIG1zZy50ZXh0Q29udGVudCA9IG4rJyB3b3JrZXJzJzsKfQokKCdzYXZlUG93ZXInKS5vbmNsaWNrID0gKCkgPT4geyB2b2lkIHNhdmVXb3JrZXJzKCQoJ3NldFdvcmtlcnMnKS52YWx1ZSk7IH07CiQoJ3NldFdvcmtlcnMnKS5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgZSA9PiB7IGlmIChlLmtleSA9PT0gJ0VudGVyJykgJCgnc2F2ZVBvd2VyJykuY2xpY2soKTsgfSk7CiQoJ3NhdmVIb29rJykub25jbGljayA9IGFzeW5jICgpID0+IHsKICBjb25zdCB0ZXh0ID0gJCgnc2V0V2ViaG9vaycpLnZhbHVlLnRyaW0oKTsKICB0cnkgewogICAgY29uc3QgcmVzID0gYXdhaXQgYXBpKCdvZmR0UHJvZmlsZScsIHsgd2ViaG9vazogdGV4dCB9KTsKICAgIGlmIChyZXMub2spIHsKICAgICAgc3RhdGUgPSBPYmplY3QuYXNzaWduKHN0YXRlLCByZXMuc3RhdGUpOwogICAgICBzdGF0ZS53ZWJob29rID0gdGV4dDsKICAgIH0KICAgICQoJ3NldEhvb2tNc2cnKS50ZXh0Q29udGVudCA9IHRleHQgPyAnU2F2ZWQnIDogJ0NsZWFyZWQnOwogIH0gY2F0Y2goZSkgeyAkKCdzZXRIb29rTXNnJykudGV4dENvbnRlbnQgPSAnQ291bGQgbm90IHNhdmUnOyB9Cn07CiQoJ29wZW5HdWlkZScpLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgY29uc3Qgb2sgPSBhd2FpdCBhc2soJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBvcGVuIHRoZSBzZXR1cCBndWlkZT8nLCAnVGhpcyB0YWtlcyB5b3UgdGhyb3VnaCB0aGUgZmlyc3QtcnVuIHN0ZXBzIGFnYWluLicsICdPcGVuJyk7CiAgaWYgKCFvaykgcmV0dXJuOwogIHNldHVwU3RlcCA9IDA7IHNob3dTZXR1cCh0cnVlKTsKfTsKYXN5bmMgZnVuY3Rpb24gZmx1c2hTZXR0aW5ncygpewogIHRyeSB7CiAgICBjb25zdCBwcm94aWVzID0gJCgnc2V0UHJveGllcycpLnZhbHVlOwogICAgY29uc3Qgd2ViaG9vayA9ICQoJ3NldFdlYmhvb2snKS52YWx1ZTsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgnb2ZkdFByb2ZpbGUnLCB7IHByb3hpZXM6IHByb3hpZXMsIHdlYmhvb2s6IHdlYmhvb2sgfSk7CiAgICBpZiAocmVzICYmIHJlcy5vaykgewogICAgICBzdGF0ZSA9IE9iamVjdC5hc3NpZ24oc3RhdGUsIHJlcy5zdGF0ZSk7CiAgICAgIHN0YXRlLnByb3hpZXMgPSBwcm94aWVzOwogICAgICBzdGF0ZS53ZWJob29rID0gd2ViaG9vazsKICAgIH0KICB9IGNhdGNoKGUpIHt9Cn0KCiQoJ2xvZ291dCcpLm9uY2xpY2sgPSAoKSA9PiB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7Cgphc3luYyBmdW5jdGlvbiBjaGVja1VwZGF0ZSgpewogIHRyeSB7CiAgICBjb25zdCB1ID0gYXdhaXQgYXBpKCdvZmR0VXBkYXRlJywge30pOwogICAgaWYgKHUgJiYgdS5uZXdlciAmJiB1LnJlbW90ZSkgewogICAgICBjb25zdCBiID0gJCgndXBkQmFubmVyJyk7CiAgICAgIGIudGV4dENvbnRlbnQgPSAnQnVpbGQgJyt1LnJlbW90ZSsnIGlzIGxpdmUuIFlvdSBhcmUgb24gJyt1LmxvY2FsKycuIENsaWNrIHRvIGdldCBpdC4nOwogICAgICBiLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgICBiLnN0eWxlLmN1cnNvciA9ICdwb2ludGVyJzsKICAgICAgYi5vbmNsaWNrID0gKCkgPT4gewogICAgICAgIGlmICh1LnVybCkgewogICAgICAgICAgdHJ5IHsgd2luZG93Lm9mZHRPcGVuVXJsKEpTT04uc3RyaW5naWZ5KHt1cmw6IHUudXJsfSkpOyB9IGNhdGNoKGUpIHt9CiAgICAgICAgfQogICAgICB9OwogICAgfQogIH0gY2F0Y2goZSkge30KfQoKZnVuY3Rpb24gc3RvcFJ1bigpewogIHJ1bm5pbmcgPSBmYWxzZTsKICBydW5TdG9wcGVkID0gdHJ1ZTsKICBydW5TZXErKzsKICBsb2dRID0gW107CiAgc3RvcExvZ1RpY2soKTsKICB0cnkgeyB3aW5kb3cub2ZkdFN0b3AoJ3t9Jyk7IH0gY2F0Y2goZSkge30KfQoKZnVuY3Rpb24gZW5kUnVuKCl7CiAgcnVubmluZyA9IGZhbHNlOwogICQoJ3N0YXJ0JykuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7ICQoJ3N0b3AnKS5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsKICAkKCdzdG9wJykudGV4dENvbnRlbnQgPSAnU3RvcCc7CiAgJCgnc2NhbkknKS5jbGFzc0xpc3QuYWRkKCdoaWRkZW4nKTsgJCgncnVuU3RhdGUnKS50ZXh0Q29udGVudCA9IHN0YXRzLmNoZWNrZWQgPyAnSWRsZScgOiAnUmVhZHknOwogIHJlbmRlck1vZGVzKCk7Cn0KCndpbmRvdy5fX29mZHRQdXNoID0gZnVuY3Rpb24ocGF5bG9hZCl7CiAgaWYgKCFydW5uaW5nKSByZXR1cm47CiAgY29uc3Qgcm93cyA9ICgocGF5bG9hZCAmJiBwYXlsb2FkLnJlc3VsdHMpIHx8IFtdKS5maWx0ZXIociA9PiB7CiAgICBjb25zdCBzdCA9IHIgJiYgci5zdGF0dXM7CiAgICByZXR1cm4gc3Q9PT0nYXZhaWxhYmxlJyB8fCBzdD09PSd0YWtlbic7CiAgfSk7CiAgZm9yIChjb25zdCByIG9mIHJvd3MpIHF1ZXVlTG9nKHIuc3RhdHVzLCByLnVzZXJuYW1lIHx8ICcnKTsKICBpZiAocGF5bG9hZCAmJiBwYXlsb2FkLnN0YXRzKSB7CiAgICBzdGF0cy5jaGVja2VkID0gcGF5bG9hZC5zdGF0cy5jaGVja2VkIHx8IDA7CiAgICBzdGF0cy5hdmFpbGFibGUgPSBwYXlsb2FkLnN0YXRzLmF2YWlsYWJsZSB8fCAwOwogICAgc3RhdHMudGFrZW4gPSBwYXlsb2FkLnN0YXRzLnRha2VuIHx8IDA7CiAgICBzdGF0cy5lcnJvcnMgPSBwYXlsb2FkLnN0YXRzLmVycm9ycyB8fCAwOwogIH0gZWxzZSB7CiAgICBmb3IgKGNvbnN0IHIgb2Ygcm93cykgewogICAgICBjb25zdCBzdCA9IHIuc3RhdHVzOwogICAgICBpZiAoc3QhPT0nYXZhaWxhYmxlJyAmJiBzdCE9PSd0YWtlbicpIGNvbnRpbnVlOwogICAgICBzdGF0cy5jaGVja2VkKys7CiAgICAgIGlmIChzdD09PSdhdmFpbGFibGUnKSBzdGF0cy5hdmFpbGFibGUrKzsKICAgICAgZWxzZSBzdGF0cy50YWtlbisrOwogICAgfQogIH0KICBpZiAocGF5bG9hZCAmJiBwYXlsb2FkLmhpdHMgJiYgcGF5bG9hZC5oaXRzLmxlbmd0aCkgewogICAgc3RhdGUuaGl0cyA9IHBheWxvYWQuaGl0cy5jb25jYXQoc3RhdGUuaGl0c3x8W10pOwogIH0KICBzY2hlZHVsZVBhaW50KCk7Cn07CndpbmRvdy5fX29mZHREb25lID0gZnVuY3Rpb24oKXsKICBjb25zdCBuYXR1cmFsID0gcnVubmluZyAmJiAhcnVuU3RvcHBlZDsKICBjb25zdCBsaXN0RG9uZSA9IG5hdHVyYWwgJiYgKGxhc3RSdW5Nb2RlID09PSAnbGlzdCcgfHwgbGFzdFJ1bk1vZGUgPT09ICd3b3JkcycgfHwgbGFzdFJ1bk1vZGUgPT09ICdzZW1pJykgJiYgIWxhc3RSdW5JbmY7CiAgY29uc3QgY2hlY2tlZCA9IHN0YXRzLmNoZWNrZWQ7CiAgY29uc3QgYXZhaWwgPSBzdGF0cy5hdmFpbGFibGU7CiAgZmx1c2hMb2coZmFsc2UpOwogIGVuZFJ1bigpOwogIGlmIChsaXN0RG9uZSkgewogICAgY29uc3QgZ290ID0gYXZhaWwgPT09IDEgPyAnMSBhdmFpbGFibGUgbmFtZScgOiBhdmFpbCsnIGF2YWlsYWJsZSBuYW1lcyc7CiAgICBjb25zdCB3aGVyZSA9IGF2YWlsID8gJyBPcGVuIEhpdHMgaW4gdGhlIHNpZGViYXIgdG8gc2VlIHRoZW0uJyA6ICcgTm8gYXZhaWxhYmxlIG5hbWVzIHRoaXMgcnVuLic7CiAgICBhc2soJ0FsbCBuYW1lcyBjaGVja2VkJywgJ0NoZWNrZWQgJytjaGVja2VkKycgbmFtZXMuIFlvdSBnb3QgJytnb3QrJy4nK3doZXJlLCBhdmFpbCA/ICdPcGVuIEhpdHMnIDogJ09LJywgZmFsc2UsICFhdmFpbCwgJ1N0YXknKS50aGVuKChvaykgPT4gewogICAgICBpZiAob2sgJiYgYXZhaWwpIHNldFZpZXcoJ2hpdHMnKTsKICAgIH0pOwogIH0KfTsKCiQoJ3N0YXJ0Jykub25jbGljayA9IGFzeW5jICgpID0+IHsKICBpZiAocnVubmluZykgcmV0dXJuOwogIGNvbnN0IHByb3h5VGV4dCA9IHN0YXRlLnByb3hpZXMgfHwgJCgnc2V0UHJveGllcycpLnZhbHVlIHx8ICcnOwogIGlmIChwcm94eUxpbmVzKHByb3h5VGV4dCkgPCAxKSB7CiAgICBhc2soJ0FkZCBwcm94aWVzIGZpcnN0JywgJ1RoZSBjaGVja2VyIG5lZWRzIHByb3hpZXMuIEl0IHdpbGwgbm90IHN0YXJ0IHdpdGhvdXQgdGhlbS4nLCAnT0snLCBmYWxzZSwgdHJ1ZSk7CiAgICByZXR1cm47CiAgfQogIGlmIChwbGF0RG93bihwbGF0Zm9ybSkpIHsgbm90aWNlRG93bigpOyByZXR1cm47IH0KICBjb25zdCBwbGF0ID0gcGxhdGZvcm07CiAgY29uc3QgbWQgPSBtb2RlOwogIGNvbnN0IGxpc3RUZXh0ID0gJCgnbGlzdCcpLnZhbHVlOwogIHJ1bm5pbmcgPSB0cnVlOwogIHJ1blN0b3BwZWQgPSBmYWxzZTsKICBsYXN0UnVuTW9kZSA9IG1kOwogIGxhc3RSdW5JbmYgPSAkKCdpbmYnKS5jaGVja2VkOwogIHJ1blNlcSsrOwogICQoJ3N0YXJ0JykuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7ICQoJ3N0b3AnKS5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICAkKCdzdG9wJykuaW5uZXJIVE1MID0gJzxzcGFuIGNsYXNzPSJzcGlubmVyIj48L3NwYW4+U3RvcCc7CiAgJCgnc2NhbkknKS5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsgJCgncnVuU3RhdGUnKS50ZXh0Q29udGVudCA9ICdSdW5uaW5nICcrbWQudG9VcHBlckNhc2UoKSsnIMK3ICcrcHJveHlMaW5lcyhwcm94eVRleHQpKycgcHJveGllcyDCtyAnK3N0YXRlLndvcmtlcnMrJyB3b3JrZXJzJzsKICBzdGF0cyA9IHtjaGVja2VkOjAsYXZhaWxhYmxlOjAsdGFrZW46MCxlcnJvcnM6MH07CiAgY29uc3QgbG9nID0gJCgnbG9nJyk7IGxvZy50ZXh0Q29udGVudD0nJzsgbG9nLmRhdGFzZXQucmVhZHkgPSAnMCc7CiAgcGFpbnRTdGF0cygpOwogIHJlbmRlck1vZGVzKCk7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgnb2ZkdFN0YXJ0JywgewogICAgICBwbGF0Zm9ybTogcGxhdCwKICAgICAgbW9kZTogbWQsCiAgICAgIGxpc3Q6IGxpc3RUZXh0LAogICAgICBwcm94aWVzOiBwcm94eVRleHQsCiAgICAgIGluZjogJCgnaW5mJykuY2hlY2tlZCwKICAgICAgd29yZGxpc3Q6IHdvcmRsaXN0CiAgICB9KTsKICAgIGlmICghcmVzIHx8ICFyZXMub2spIHsKICAgICAgcnVubmluZyA9IGZhbHNlOwogICAgICBsb2dMaW5lKCd1bmtub3duJywgKHJlcyAmJiByZXMuZXJyb3IpIHx8ICdDb3VsZCBub3Qgc3RhcnQnKTsKICAgICAgZW5kUnVuKCk7CiAgICB9CiAgfSBjYXRjaChlKSB7CiAgICBydW5uaW5nID0gZmFsc2U7CiAgICBsb2dMaW5lKCd1bmtub3duJywgJ0NvdWxkIG5vdCBzdGFydCcpOwogICAgZW5kUnVuKCk7CiAgfQp9OwokKCdzdG9wJykub25jbGljayA9ICgpID0+IHsKICBzdG9wUnVuKCk7CiAgZW5kUnVuKCk7Cn07CiQoJ3Jlc2V0Jykub25jbGljayA9IGFzeW5jICgpID0+IHsKICBpZiAocnVubmluZyB8fCAoJCgnbG9nJykuZGF0YXNldC5yZWFkeSA9PT0gJzEnKSkgewogICAgY29uc3Qgb2sgPSBhd2FpdCBhc2soJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byByZXNldCB0aGlzIGNoZWNrPycsICdUaGUgbGl2ZSBsb2cgYW5kIGNvdW50cyB3aWxsIGJlIGNsZWFyZWQuJywgJ1Jlc2V0JywgdHJ1ZSk7CiAgICBpZiAoIW9rKSByZXR1cm47CiAgfQogIHN0b3BSdW4oKTsKICBzdGF0cyA9IHtjaGVja2VkOjAsYXZhaWxhYmxlOjAsdGFrZW46MCxlcnJvcnM6MH07CiAgJCgnbG9nJykudGV4dENvbnRlbnQgPSAnV2FpdGluZyc7CiAgJCgnbG9nJykuZGF0YXNldC5yZWFkeSA9ICcwJzsKICBsb2dRID0gW107CiAgc3RvcExvZ1RpY2soKTsKICBpZiAocGFpbnRSYWYpIHsgY2FuY2VsQW5pbWF0aW9uRnJhbWUocGFpbnRSYWYpOyBwYWludFJhZiA9IDA7IH0KICBlbmRSdW4oKTsKICAkKCdydW5TdGF0ZScpLnRleHRDb250ZW50ID0gJ1JlYWR5JzsKICBwYWludFN0YXRzKCk7Cn07CgpmdW5jdGlvbiBtYWtlTG9nUm93KHN0LCBuYW1lLCBhbmltYXRlKXsKICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICByb3cuY2xhc3NOYW1lID0gJ3Jvdyc7CiAgY29uc3QgdGFnID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpOwogIGNvbnN0IHRyYW5zaWVudCA9IHN0PT09J3Vua25vd24nIHx8IHN0PT09J2Vycm9yJyB8fCBzdD09PSdyYXRlJyB8fCBzdD09PSdwcm94eSc7CiAgdGFnLmNsYXNzTmFtZSA9IHN0PT09J2F2YWlsYWJsZScgPyAnb2snIDogdHJhbnNpZW50ID8gJ2JhZCcgOiAnbm8nOwogIHRhZy50ZXh0Q29udGVudCA9IHN0PT09J2F2YWlsYWJsZScgPyAnWytdJyA6IHRyYW5zaWVudCA/ICdbfl0nIDogJ1stXSc7CiAgaWYgKGFuaW1hdGUpIHsKICAgIGlmIChzdD09PSdhdmFpbGFibGUnKSByb3cuY2xhc3NMaXN0LmFkZCgnaGl0LW9rJyk7CiAgICBlbHNlIGlmICghdHJhbnNpZW50KSByb3cuY2xhc3NMaXN0LmFkZCgnaGl0LW5vJyk7CiAgfQogIGNvbnN0IG5tID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpOwogIG5tLmNsYXNzTmFtZSA9ICduYW1lJzsKICBjb25zdCB1bmtub3duID0gc3Q9PT0ndW5rbm93bicgfHwgc3Q9PT0nZXJyb3InOwogIG5tLnRleHRDb250ZW50ID0gbmFtZSB8fCAndW5rbm93bic7CiAgY29uc3QgbGFiID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpOwogIGxhYi5jbGFzc05hbWUgPSAnbGFiJzsKICBsYWIudGV4dENvbnRlbnQgPSBzdGF0dXNMYWJlbChzdCk7CiAgcm93LmFwcGVuZENoaWxkKHRhZyk7IHJvdy5hcHBlbmRDaGlsZChubSk7IHJvdy5hcHBlbmRDaGlsZChsYWIpOwogIHJldHVybiByb3c7Cn0KbGV0IGxvZ1EgPSBbXTsKbGV0IHBhaW50UmFmID0gMDsKbGV0IGxvZ1RpY2sgPSAwOwpmdW5jdGlvbiBxdWV1ZUxvZyhzdCwgbmFtZSl7CiAgaWYgKCFuYW1lKSByZXR1cm47CiAgaWYgKHN0IT09J2F2YWlsYWJsZScgJiYgc3QhPT0ndGFrZW4nKSByZXR1cm47CiAgbG9nUS5wdXNoKHtzdCwgbmFtZX0pOwogIGlmIChsb2dRLmxlbmd0aCA+IDEwMCkgewogICAgY29uc3Qga2VlcCA9IGxvZ1EuZmlsdGVyKHggPT4geC5zdD09PSdhdmFpbGFibGUnKTsKICAgIGxvZ1EgPSBrZWVwLmNvbmNhdChsb2dRLnNsaWNlKC0zMikpOwogIH0KICBzdGFydExvZ1RpY2soKTsKfQpmdW5jdGlvbiBzdGFydExvZ1RpY2soKXsKICBpZiAobG9nVGljaykgcmV0dXJuOwogIGxvZ1RpY2sgPSBzZXRJbnRlcnZhbChkcmlwTG9nLCAyOCk7Cn0KZnVuY3Rpb24gc3RvcExvZ1RpY2soKXsKICBpZiAoIWxvZ1RpY2spIHJldHVybjsKICBjbGVhckludGVydmFsKGxvZ1RpY2spOwogIGxvZ1RpY2sgPSAwOwp9CmZ1bmN0aW9uIGRyaXBMb2coKXsKICBjb25zdCBlbCA9ICQoJ2xvZycpOwogIGlmICghZWwpIHJldHVybjsKICBpZiAoIWxvZ1EubGVuZ3RoKSB7CiAgICBpZiAoIXJ1bm5pbmcpIHN0b3BMb2dUaWNrKCk7CiAgICByZXR1cm47CiAgfQogIGlmIChlbC5kYXRhc2V0LnJlYWR5ICE9PSAnMScpIHsgZWwudGV4dENvbnRlbnQgPSAnJzsgZWwuZGF0YXNldC5yZWFkeSA9ICcxJzsgfQogIGNvbnN0IGl0ZW0gPSBsb2dRLnNoaWZ0KCk7CiAgZWwuYXBwZW5kQ2hpbGQobWFrZUxvZ1JvdyhpdGVtLnN0LCBpdGVtLm5hbWUsIGl0ZW0uc3Q9PT0nYXZhaWxhYmxlJykpOwogIHdoaWxlIChlbC5jaGlsZE5vZGVzLmxlbmd0aCA+IDQ4KSBlbC5yZW1vdmVDaGlsZChlbC5maXJzdENoaWxkKTsKICBlbC5zY3JvbGxUb3AgPSBlbC5zY3JvbGxIZWlnaHQ7Cn0KZnVuY3Rpb24gZmx1c2hMb2coZm9yY2UpewogIGlmICghZm9yY2UpIHsKICAgIGRyaXBMb2coKTsKICAgIHJldHVybjsKICB9CiAgY29uc3QgZWwgPSAkKCdsb2cnKTsKICBpZiAoIWVsKSB7IGxvZ1EgPSBbXTsgcmV0dXJuOyB9CiAgaWYgKCFsb2dRLmxlbmd0aCkgcmV0dXJuOwogIGlmIChlbC5kYXRhc2V0LnJlYWR5ICE9PSAnMScpIHsgZWwudGV4dENvbnRlbnQgPSAnJzsgZWwuZGF0YXNldC5yZWFkeSA9ICcxJzsgfQogIGNvbnN0IGl0ZW0gPSBsb2dRLnNoaWZ0KCk7CiAgZWwuYXBwZW5kQ2hpbGQobWFrZUxvZ1JvdyhpdGVtLnN0LCBpdGVtLm5hbWUsIGl0ZW0uc3Q9PT0nYXZhaWxhYmxlJykpOwogIHdoaWxlIChlbC5jaGlsZE5vZGVzLmxlbmd0aCA+IDQ4KSBlbC5yZW1vdmVDaGlsZChlbC5maXJzdENoaWxkKTsKICBlbC5zY3JvbGxUb3AgPSBlbC5zY3JvbGxIZWlnaHQ7Cn0KZnVuY3Rpb24gbG9nTGluZShzdCwgbmFtZSl7CiAgcXVldWVMb2coc3QsIG5hbWUpOwogIHNjaGVkdWxlUGFpbnQoKTsKfQpmdW5jdGlvbiBwYWludFN0YXRzKCl7CiAgJCgncy1jaGVja2VkJykudGV4dENvbnRlbnQgPSBzdGF0cy5jaGVja2VkOwogICQoJ3MtYXZhaWwnKS50ZXh0Q29udGVudCA9IHN0YXRzLmF2YWlsYWJsZTsKICAkKCdzLXRha2VuJykudGV4dENvbnRlbnQgPSBzdGF0cy50YWtlbjsKICAkKCdzLWVycicpLnRleHRDb250ZW50ID0gc3RhdHMuZXJyb3JzOwp9CmZ1bmN0aW9uIHNjaGVkdWxlUGFpbnQoKXsKICBpZiAocGFpbnRSYWYpIHJldHVybjsKICBwYWludFJhZiA9IHJlcXVlc3RBbmltYXRpb25GcmFtZSgoKSA9PiB7CiAgICBwYWludFJhZiA9IDA7CiAgICBwYWludFN0YXRzKCk7CiAgICBjb25zdCBoaXRzID0gJCgncy1oaXRzJyk7CiAgICBpZiAoaGl0cykgaGl0cy50ZXh0Q29udGVudCA9IChzdGF0ZS5oaXRzfHxbXSkubGVuZ3RoOwogIH0pOwp9CmFzeW5jIGZ1bmN0aW9uIGNvcHlUZXh0KHQpewogIHQgPSBTdHJpbmcodCB8fCAnJyk7CiAgaWYgKCF0KSByZXR1cm4gZmFsc2U7CiAgdHJ5IHsKICAgIGF3YWl0IG5hdmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KHQpOwogICAgcmV0dXJuIHRydWU7CiAgfSBjYXRjaChlKSB7fQogIHRyeSB7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoJ29mZHRDb3B5JywgeyB0ZXh0OiB0IH0pOwogICAgcmV0dXJuICEhKHJlcyAmJiByZXMub2spOwogIH0gY2F0Y2goZSkge30KICByZXR1cm4gZmFsc2U7Cn0KZnVuY3Rpb24gcmVuZGVySGl0cygpewogIGNvbnN0IGJveCA9ICQoJ2hpdExpc3QnKTsKICBpZiAoIWJveCkgcmV0dXJuOwogIGNvbnN0IGhpdHMgPSBzdGF0ZS5oaXRzfHxbXTsKICBib3gucmVwbGFjZUNoaWxkcmVuKCk7CiAgaWYgKCFoaXRzLmxlbmd0aCkgewogICAgY29uc3QgZW1wdHkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGVtcHR5LmNsYXNzTmFtZSA9ICdwYW5lbCc7CiAgICBlbXB0eS5zdHlsZS5jc3NUZXh0ID0gJ3BhZGRpbmc6NDBweDt0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjp2YXIoLS1tdXRlZCknOwogICAgZW1wdHkudGV4dENvbnRlbnQgPSAnTm90aGluZyBzYXZlZCB5ZXQuJzsKICAgIGJveC5hcHBlbmRDaGlsZChlbXB0eSk7CiAgICByZXR1cm47CiAgfQogIGNvbnN0IGZyYWcgPSBkb2N1bWVudC5jcmVhdGVEb2N1bWVudEZyYWdtZW50KCk7CiAgY29uc3QgbWFueSA9IGhpdHMubGVuZ3RoID4gODA7CiAgZm9yIChsZXQgaSA9IDA7IGkgPCBoaXRzLmxlbmd0aDsgaSsrKSB7CiAgICBjb25zdCBoID0gaGl0c1tpXTsKICAgIGNvbnN0IGQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGQuY2xhc3NOYW1lID0gJ2hpdCc7CiAgICBkLmRhdGFzZXQudSA9IGgudXNlcm5hbWUgfHwgJyc7CiAgICBpZiAobWFueSkgZC5zdHlsZS5hbmltYXRpb24gPSAnbm9uZSc7CiAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBsZWZ0LnN0eWxlLmZsZXggPSAnMSc7CiAgICBjb25zdCBiID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYicpOwogICAgYi50ZXh0Q29udGVudCA9ICdAJyArIChoLnVzZXJuYW1lIHx8ICcnKTsKICAgIGNvbnN0IGsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGsuY2xhc3NOYW1lID0gJ2tpY2tlcic7CiAgICBrLnRleHRDb250ZW50ID0gaC5wbGF0Zm9ybSB8fCAnJzsKICAgIGxlZnQuYXBwZW5kQ2hpbGQoYik7CiAgICBsZWZ0LmFwcGVuZENoaWxkKGspOwogICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyk7CiAgICBiYWRnZS5jbGFzc05hbWUgPSAnb2snOwogICAgYmFkZ2UudGV4dENvbnRlbnQgPSAnc2F2ZWQnOwogICAgZC5hcHBlbmRDaGlsZChsZWZ0KTsKICAgIGQuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgZnJhZy5hcHBlbmRDaGlsZChkKTsKICB9CiAgYm94LmFwcGVuZENoaWxkKGZyYWcpOwogIGlmICghYm94Ll9oaXRDbGljaykgewogICAgYm94Ll9oaXRDbGljayA9IHRydWU7CiAgICBib3guYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZSkgPT4gewogICAgICBjb25zdCBkID0gZS50YXJnZXQuY2xvc2VzdCgnLmhpdCcpOwogICAgICBpZiAoIWQpIHJldHVybjsKICAgICAgY29uc3QgdSA9IGQuZGF0YXNldC51IHx8ICcnOwogICAgICB2b2lkIGNvcHlUZXh0KHUpLnRoZW4oKG9rKSA9PiB7CiAgICAgICAgaWYgKCFvaykgcmV0dXJuOwogICAgICAgIGNvbnN0IGJhZGdlID0gZC5xdWVyeVNlbGVjdG9yKCcub2snKTsKICAgICAgICBpZiAoYmFkZ2UpIHsKICAgICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gJ2NvcGllZCc7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsgYmFkZ2UudGV4dENvbnRlbnQgPSAnc2F2ZWQnOyB9LCAxMjAwKTsKICAgICAgICB9CiAgICAgIH0pOwogICAgfSk7CiAgfQp9CiQoJ2NvcHlIaXRzJykub25jbGljayA9ICgpID0+IHsgdm9pZCBjb3B5VGV4dCgoc3RhdGUuaGl0c3x8W10pLm1hcChoPT5oLnVzZXJuYW1lKS5qb2luKCdcbicpKTsgfTsKJCgnY2xlYXJIaXRzJykub25jbGljayA9IGFzeW5jICgpID0+IHsKICBpZiAoIShzdGF0ZS5oaXRzfHxbXSkubGVuZ3RoKSByZXR1cm47CiAgY29uc3Qgb2sgPSBhd2FpdCBhc2soJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBjbGVhciBzYXZlZCBoaXRzPycsICdUaGlzIHJlbW92ZXMgdGhlIHNhdmVkIGhpdHMgZnJvbSB0aGlzIGxvY2FsIGFwcC4nLCAnQ2xlYXInLCB0cnVlKTsKICBpZiAoIW9rKSByZXR1cm47CiAgdHJ5IHsgYXdhaXQgYXBpKCdvZmR0Q2xlYXJIaXRzJyk7IH0gY2F0Y2goZSkge30KICBzdGF0ZS5oaXRzPVtdOyByZW5kZXJIaXRzKCk7ICQoJ3MtaGl0cycpLnRleHRDb250ZW50PScwJzsKfTsKCihhc3luYyAoKSA9PiB7CiAgZm9yIChsZXQgaSA9IDA7IGkgPCAxMjsgaSsrKSB7CiAgICB0cnkgewogICAgICBjb25zdCBqID0gYXdhaXQgYXBpKCdvZmR0U3RhdGUnKTsKICAgICAgaWYgKGogJiYgai5vayAmJiBqLnN0YXRlKSB7CiAgICAgICAgZW50ZXIoai5zdGF0ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICB9IGNhdGNoKGUpIHt9CiAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgNjApKTsKICB9Cn0pKCk7CnJlcXVlc3RBbmltYXRpb25GcmFtZSgoKSA9PiByZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCkgPT4gewogIHRyeSB7IHdpbmRvdy5vZmR0UmVhZHkoKTsgfSBjYXRjaChlKSB7fQp9KSk7Cjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4=")
HOST = "127.0.0.1"
PREFERRED_PORT = 39182

DEFAULT_STATE = {
    "username": "sniperr",
    "pfp": "",
    "version": "4.3",
    "proxies": "",
    "webhook": "",
    "setupDone": True,
    "wordlist": "english",
    "workers": 250,
    "hits": [],
}

state_lock = threading.RLock()
state: dict[str, Any] = dict(DEFAULT_STATE)

run_lock = threading.RLock()
checker_thread: Optional[threading.Thread] = None
stop_event = threading.Event()
checker_running = False

stats_lock = threading.RLock()
stats = {"checked": 0, "available": 0, "taken": 0, "errors": 0}

clients_lock = threading.RLock()
clients: set[queue.Queue[str]] = set()


def _clamp_workers(value: Any) -> int:
    try:
        n = int(value)
    except Exception:
        n = 250
    return max(1, min(engine.MAX_WORKERS, n))


def load_state() -> None:
    global state
    merged = dict(DEFAULT_STATE)
    if STATE_FILE.exists():
        try:
            raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k in DEFAULT_STATE:
                    if k in raw:
                        merged[k] = raw[k]
        except Exception:
            pass
    merged["workers"] = _clamp_workers(merged.get("workers", 250))
    merged["setupDone"] = True
    if not isinstance(merged.get("hits"), list):
        merged["hits"] = []
    merged["hits"] = merged["hits"][:5000]
    state = merged


def save_state() -> None:
    with state_lock:
        payload = {k: state.get(k, DEFAULT_STATE[k]) for k in DEFAULT_STATE}
        payload["workers"] = _clamp_workers(payload.get("workers"))
        payload["setupDone"] = True
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError:
        pass


def public_state() -> dict[str, Any]:
    with state_lock:
        return {
            "username": state.get("username", "sniperr"),
            "pfp": state.get("pfp", ""),
            "version": state.get("version", "4.3"),
            "proxies": state.get("proxies", ""),
            "webhook": state.get("webhook", ""),
            "setupDone": True,
            "wordlist": state.get("wordlist", "english"),
            "workers": _clamp_workers(state.get("workers", 250)),
            "hits": list(state.get("hits", [])),
        }


def broadcast(event_type: str, payload: Any = None) -> None:
    raw = json.dumps({"type": event_type, "payload": payload}, separators=(",", ":"))
    with clients_lock:
        dead: list[queue.Queue[str]] = []
        for q in clients:
            try:
                q.put_nowait(raw)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(raw)
                except Exception:
                    dead.append(q)
        for q in dead:
            clients.discard(q)


def parse_proxies(text: str) -> list[str]:
    rows: list[str] = []
    for line in (text or "").replace(",", "\n").splitlines():
        p = engine.normalize_proxy(line)
        if p:
            rows.append(p)
    # Keep order while deduping.
    return list(dict.fromkeys(rows))


def make_name_source(mode: str, list_text: str, wordlist: str, loop: bool) -> tuple[Callable[[], Optional[str]], Optional[int]]:
    if mode == "list":
        names = [x.strip() for x in (list_text or "").splitlines() if x.strip()]
        if not names:
            raise ValueError("Paste at least one name for List mode")
        index = 0

        def next_name() -> Optional[str]:
            nonlocal index
            if not loop and index >= len(names):
                return None
            name = names[index % len(names)]
            index += 1
            return name

        return next_name, None if loop else len(names)

    if mode == "words":
        engine_mode = "word_short" if wordlist == "short" else "word_dict"
    elif mode == "semi":
        engine_mode = "semi_3c_both"
    else:
        engine_mode = {
            "3l": "3l",
            "4l": "4l",
            "3c": "3c_smart",
            "4c": "4c_smart",
            "3n": "3n",
            "4n": "4n",
            "5n": "5n",
        }.get(mode)
    if not engine_mode:
        raise ValueError(f"Unsupported mode: {mode}")

    gen = engine.NameGenerator(engine_mode)
    emitted = 0

    def next_name() -> Optional[str]:
        nonlocal emitted
        if not loop and emitted >= gen.total:
            return None
        emitted += 1
        return gen.next()

    return next_name, None if loop else gen.total


def _snapshot_stats() -> dict[str, int]:
    with stats_lock:
        return dict(stats)


def _append_hit(username: str, platform: str) -> dict[str, str]:
    hit = {"username": username, "platform": platform}
    with state_lock:
        existing = state.setdefault("hits", [])
        if not any(h.get("username") == username and h.get("platform") == platform for h in existing[:5000] if isinstance(h, dict)):
            existing.insert(0, hit)
            del existing[5000:]
    return hit


def checker_worker(req: dict[str, Any]) -> None:
    global checker_running
    platform = str(req.get("platform") or "discord").lower()
    mode = str(req.get("mode") or "4l").lower()
    list_text = str(req.get("list") or "")
    loop = bool(req.get("inf"))
    wordlist = str(req.get("wordlist") or "english")
    proxy_text = str(req.get("proxies") or "")

    webhook_sender = None
    try:
        if platform != "discord":
            broadcast("push", {"results": [{"status": "error", "username": "Discord only in this build"}], "stats": _snapshot_stats(), "hits": []})
            return

        proxies = parse_proxies(proxy_text)
        if not proxies:
            broadcast("push", {"results": [{"status": "error", "username": "No valid proxies loaded"}], "stats": _snapshot_stats(), "hits": []})
            return

        next_name, _total = make_name_source(mode, list_text, wordlist, loop)
        with state_lock:
            workers = _clamp_workers(state.get("workers", 250))
            webhook_url = str(state.get("webhook") or "").strip()

        checker = engine.Checker(engine.DEFAULT_TIMEOUT_MS, proxies)
        target_cps = float(engine.DEFAULT_CPS)
        submit_interval = 1.0 / max(engine.MIN_CPS, target_cps)

        if webhook_url and engine.looks_like_discord_webhook(webhook_url):
            webhook_sender = engine.WebhookSender(webhook_url)
            webhook_sender.start()

        result_batch: list[dict[str, str]] = []
        hit_batch: list[dict[str, str]] = []
        last_flush = time.monotonic()
        save_dirty = False

        def flush(force: bool = False) -> None:
            nonlocal result_batch, hit_batch, last_flush, save_dirty
            now = time.monotonic()
            if not force and len(result_batch) < 40 and now - last_flush < 0.12:
                return
            if result_batch or hit_batch:
                broadcast("push", {"results": result_batch, "stats": _snapshot_stats(), "hits": hit_batch})
                result_batch = []
                hit_batch = []
            if save_dirty and (force or now - last_flush >= 0.5):
                save_state()
                save_dirty = False
            last_flush = now

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sniperr-ui") as pool:
            inflight: dict[Any, str] = {}
            exhausted = False
            next_submit_at = time.monotonic()

            while not stop_event.is_set():
                now = time.monotonic()
                while not exhausted and len(inflight) < workers and now >= next_submit_at and not stop_event.is_set():
                    name = next_name()
                    if name is None:
                        exhausted = True
                        break
                    fut = pool.submit(engine._check_one, checker, name)
                    inflight[fut] = name
                    next_submit_at += submit_interval
                    if next_submit_at < now - 0.05:
                        next_submit_at = now
                    now = time.monotonic()

                if exhausted and not inflight:
                    break

                if not inflight:
                    time.sleep(0.002)
                    continue

                done, _ = wait(tuple(inflight), timeout=0.02, return_when=FIRST_COMPLETED)
                if not done:
                    flush(False)
                    continue

                for fut in done:
                    fallback_name = inflight.pop(fut, "?")
                    try:
                        checked_name, result = fut.result()
                    except Exception:
                        checked_name = fallback_name
                        result = engine.CheckResult("error", detail="worker error")

                    status = result.state
                    with stats_lock:
                        stats["checked"] += 1
                        if status == "available":
                            stats["available"] += 1
                        elif status == "taken":
                            stats["taken"] += 1
                        else:
                            stats["errors"] += 1

                    ui_status = status
                    if status == "rate_limited":
                        ui_status = "rate"
                    elif status not in ("available", "taken"):
                        ui_status = "error"
                    result_batch.append({"status": ui_status, "username": checked_name})

                    if status == "available":
                        hit = _append_hit(checked_name, platform)
                        hit_batch.append(hit)
                        save_dirty = True
                        if webhook_sender:
                            try:
                                webhook_sender.enqueue(checked_name, mode.upper())
                            except Exception:
                                pass

                flush(False)

            # Allow already-running checks to finish briefly after Stop, then ignore the rest.
            if stop_event.is_set():
                for fut in tuple(inflight):
                    fut.cancel()
            flush(True)

    except Exception as exc:
        with stats_lock:
            stats["errors"] += 1
        broadcast("push", {"results": [{"status": "error", "username": str(exc)[:120]}], "stats": _snapshot_stats(), "hits": []})
    finally:
        if webhook_sender:
            try:
                webhook_sender.stop(drain_timeout=1.5)
            except Exception:
                pass
        save_state()
        with run_lock:
            checker_running = False
        broadcast("done", None)


class Handler(BaseHTTPRequestHandler):
    server_version = "SniperrLocal/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the runner window clean.
        return

    def _json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length)
            val = json.loads(raw.decode("utf-8"))
            return val if isinstance(val, dict) else {}
        except Exception:
            return {}

    def _send_json(self, obj: Any, status_code: int = 200) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        # Ignore query strings and always use a normalized URL path.
        path = urlsplit(self.path).path or "/"

        if path == "/api/events":
            self._events()
            return

        # Small health endpoint used by launchers/debugging.
        if path == "/api/health":
            self._send_json({"ok": True, "app": "sniperr"})
            return

        # Accept GET here too. The UI normally uses POST, but this makes startup
        # and stale-browser refreshes more tolerant.
        if path in ("/api/ofdtState", "/api/ofdtPing"):
            self._send_json({"ok": True, "state": public_state()})
            return

        # SPA fallback: any ordinary browser path renders the UI rather than a
        # BaseHTTPRequestHandler 404 page. This also fixes Edge app-mode restoring
        # an old/non-root path from a previous launch.
        if not path.startswith("/api/"):
            raw = INDEX_BYTES
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, 404)

    def _events(self) -> None:
        q: queue.Queue[str] = queue.Queue(maxsize=200)
        with clients_lock:
            clients.add(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15.0)
                    chunk = f"data: {msg}\n\n".encode("utf-8")
                except queue.Empty:
                    chunk = b": ping\n\n"
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with clients_lock:
                clients.discard(q)

    def do_POST(self) -> None:
        global checker_thread, checker_running, stats
        body = self._json_body()
        path = self.path

        if path in ("/api/ofdtState", "/api/ofdtPing"):
            self._send_json({"ok": True, "state": public_state()})
            return

        if path == "/api/ofdtProfile":
            with state_lock:
                if "username" in body:
                    username = str(body.get("username") or "").strip().lstrip("@")
                    if username:
                        state["username"] = username[:20]
                if "pfp" in body:
                    state["pfp"] = str(body.get("pfp") or "")
                if "proxies" in body:
                    state["proxies"] = str(body.get("proxies") or "")
                if "webhook" in body:
                    state["webhook"] = str(body.get("webhook") or "").strip()
                if "wordlist" in body:
                    state["wordlist"] = "short" if body.get("wordlist") == "short" else "english"
                if "workers" in body:
                    state["workers"] = _clamp_workers(body.get("workers"))
            save_state()
            self._send_json({"ok": True, "state": public_state()})
            return

        if path == "/api/ofdtSetup":
            with state_lock:
                state["setupDone"] = True
            save_state()
            self._send_json({"ok": True, "state": public_state()})
            return

        if path == "/api/ofdtStart":
            if str(body.get("platform") or "discord").lower() != "discord":
                self._send_json({"ok": False, "error": "This Sniperr build supports Discord checking only"})
                return
            proxy_text = str(body.get("proxies") or "")
            if not parse_proxies(proxy_text):
                self._send_json({"ok": False, "error": "Add at least one valid proxy first"})
                return
            try:
                make_name_source(str(body.get("mode") or "4l"), str(body.get("list") or ""), str(body.get("wordlist") or "english"), bool(body.get("inf")))
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)})
                return

            with run_lock:
                if checker_running:
                    self._send_json({"ok": False, "error": "Already running"})
                    return
                checker_running = True
                stop_event.clear()
                with stats_lock:
                    stats = {"checked": 0, "available": 0, "taken": 0, "errors": 0}
                checker_thread = threading.Thread(target=checker_worker, args=(body,), daemon=True, name="checker-main")
                checker_thread.start()
            self._send_json({"ok": True})
            return

        if path == "/api/ofdtStop":
            stop_event.set()
            self._send_json({"ok": True})
            return

        if path == "/api/ofdtClearHits":
            with state_lock:
                state["hits"] = []
            save_state()
            self._send_json({"ok": True, "state": public_state()})
            return

        if path == "/api/ofdtCopy":
            text = str(body.get("text") or "")
            ok = False
            if os.name == "nt" and text:
                try:
                    subprocess.run(["clip"], input=text, text=True, check=True, timeout=2)
                    ok = True
                except Exception:
                    pass
            self._send_json({"ok": ok})
            return

        if path == "/api/ofdtUpdate":
            self._send_json({"ok": True, "newer": False, "local": "4.3"})
            return

        if path == "/api/ofdtReady":
            self._send_json({"ok": True})
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, 404)


def open_app_window(port: int) -> None:
    if os.environ.get("SNIPERR_NO_BROWSER") == "1":
        return
    time.sleep(0.35)
    url = f"http://{HOST}:{port}/"
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("ProgramFiles", "")) / "Microsoft/Edge/Application/msedge.exe",
        ]
        for edge in candidates:
            if edge.is_file():
                try:
                    subprocess.Popen([str(edge), f"--app={url}", "--window-size=1150,750"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return
                except Exception:
                    pass
    try:
        webbrowser.open(url, new=1)
    except Exception:
        pass


def main() -> None:
    load_state()

    # Prefer the normal port, but do not fail (or accidentally show a stale app)
    # when another Sniperr/old checker process is already using it.
    try:
        server = ThreadingHTTPServer((HOST, PREFERRED_PORT), Handler)
    except OSError:
        server = ThreadingHTTPServer((HOST, 0), Handler)

    port = int(server.server_address[1])
    threading.Thread(target=open_app_window, args=(port,), daemon=True).start()
    print(f"[*] Sniperr checker local UI: http://{HOST}:{port}/")
    print("[*] Sniperr engine ready")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        save_state()
        server.server_close()


if __name__ == "__main__":
    main()
