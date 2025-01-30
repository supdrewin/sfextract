import lzma
import struct
from dataclasses import dataclass
from typing import List

LZMA_PROPS_SIZE = 5
LZMA_DIC_MIN = 1 << 12
LZMA_LIT_SIZE = 0x300
# LZMA_REQUIRED_INPUT_MAX = 20

# RC_INIT_SIZE = 5

# kNumTopBits = 24
# kTopValue = 1 << kNumTopBits

kNumBitModelTotalBits = 11
# kBitModelTotal = 1 << kNumBitModelTotalBits

# kNumMoveBits = 5

kNumPosBitsMax = 4
kNumPosStatesMax = 1 << kNumPosBitsMax

kLenNumLowBits = 3
kLenNumLowSymbols = 1 << kLenNumLowBits
kLenNumHighBits = 8
kLenNumHighSymbols = 1 << kLenNumHighBits

LenLow = 0
LenHigh = LenLow + 2 * (kNumPosStatesMax << kLenNumLowBits)
kNumLenProbs = LenHigh + kLenNumHighSymbols

# LenChoice = LenLow
# LenChoice2 = LenLow + (1 << kLenNumLowBits)

kNumStates = 12
kNumStates2 = 16
# kNumLitStates = 7

# kStartPosModelIndex = 4
kEndPosModelIndex = 14
kNumFullDistances = 1 << (kEndPosModelIndex >> 1)

kNumPosSlotBits = 6
kNumLenToPosStates = 4

kNumAlignBits = 4
kAlignTableSize = 1 << kNumAlignBits

kMatchMinLen = 2
kMatchSpecLenStart = kMatchMinLen + kLenNumLowSymbols * 2 + kLenNumHighSymbols

# kMatchSpecLen_Error_Data = 1 << 9
# kMatchSpecLen_Error_Fail = kMatchSpecLen_Error_Data - 1

kStartOffset = 1664

SpecPos = -kStartOffset
IsRep0Long = SpecPos + kNumFullDistances
RepLenCoder = IsRep0Long + (kNumStates2 << kNumPosBitsMax)
LenCoder = RepLenCoder + kNumLenProbs
IsMatch = LenCoder + kNumLenProbs
Align = IsMatch + (kNumStates2 << kNumPosBitsMax)
IsRep = Align + kAlignTableSize
IsRepG0 = IsRep + kNumStates
IsRepG1 = IsRepG0 + kNumStates
IsRepG2 = IsRepG1 + kNumStates
PosSlot = IsRepG2 + kNumStates
Literal = PosSlot + (kNumLenToPosStates << kNumPosSlotBits)
NUM_BASE_PROBS = Literal + kStartOffset
if Align != 0 and kStartOffset != 0:
    raise Exception("Align and kStartOffset are WRONG!!")

if NUM_BASE_PROBS != 1984:
    raise Exception("NUM_BASE_PROBS is WRONG!!")

kRange0 = 0xFFFFFFFF
kBound0 = (kRange0 >> kNumBitModelTotalBits) << (kNumBitModelTotalBits - 1)
kBadRepCode = kBound0 + (((kRange0 - kBound0) >> kNumBitModelTotalBits) << (kNumBitModelTotalBits - 1))
if kBadRepCode != (0xC0000000 - 0x400):
    raise Exception("kBadRepCode is WRONG!!")


@dataclass
class CLzmaProps:
    lc: int
    lp: int
    pb: int
    pad: int
    dicSize: int


@dataclass
class CLzmaDec:
    prop: CLzmaProps
    probs: List[int]
    probs_1664: int
    dic: bytes
    dicBufSize: int
    dicPos: int
    buf: bytes
    range: int
    code: int
    processedPos: int
    checkDicSize: int
    reps: List[int]
    state: int
    remainLen: int
    numProbs: int
    tempBufSize: int
    tempBuf: bytes


def easiest_decompress(data):
    return lzma.decompress(data)


def easier_decompress(data):
    return lzma.LZMADecompressor().decompress(data)


def easy_decompress(data):
    myfilter = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[:5])
    decompSize = struct.unpack("q", data[5 : 5 + 8])[0]
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[myfilter])
    ret = d.decompress(data[5 + 8 :])
    return ret[:decompSize]


def LzmaDec_InitDicAndState(p: CLzmaDec, initDic: bool, initState: bool):
    p.remainLen = kMatchSpecLenStart + 1
    p.tempBufSize = 0

    if initDic:
        p.processedPos = 0
        p.checkDicSize = 0
        p.remainLen = kMatchSpecLenStart + 2

    if initState:
        p.remainLen = kMatchSpecLenStart + 2


def LzmaProps_Decode(p: CLzmaProps, data, size):
    if size < LZMA_PROPS_SIZE:
        return "SZ_ERROR_UNSUPPORTED"

    dicSize = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24)

    if dicSize < LZMA_DIC_MIN:
        dicSize = LZMA_DIC_MIN
    p.dicSize = dicSize

    d = data[0]
    if d >= (9 * 5 * 5):
        return "SZ_ERROR_UNSUPPORTED"

    p.lc = d % 9
    p.pb = d // 9 // 5
    p.lp = d // 9 % 5
    return "SZ_OK"


def LzmaProps_GetNumProbs(p):
    return NUM_BASE_PROBS + (LZMA_LIT_SIZE << (p.lc + p.lp))


def LzmaDec_AllocateProbs2(p: CLzmaDec, props: CLzmaProps):
    numProbs = LzmaProps_GetNumProbs(props)
    p.probs = [0] * numProbs
    if not p.probs or numProbs != p.numProbs:
        # p.probs_1664 = p.probs + 1664
        p.numProbs = numProbs
    return "SZ_OK"


def LzmaDec_AllocateProbs(p: CLzmaDec, propData, propSize):
    propNew = CLzmaProps(0, 0, 0, 0, 0)
    LzmaProps_Decode(propNew, propData, propSize)
    LzmaDec_AllocateProbs2(p, propNew)
    p.prop = propNew
    return "SZ_OK"


def LzmaDec_DecodeToDic(p: CLzmaDec, src: memoryview, srcLen, finishMode, status):
    my_filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": p.prop.dicSize,
            "lc": p.prop.lc,
            "lp": p.prop.lp,
            "pb": p.prop.pb,
        }
    ]
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=my_filters)
    ret = d.decompress(src[:srcLen], p.dicBufSize)
    # The initial logic for the returned status is much more complicated, but this is a start
    status = "LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK"
    p.dicPos += len(ret)
    p.dic += ret
    return "SZ_OK", status


def decompress(data):
    inSize = len(data)
    # inlen = inSize - LZMA_PROPS_SIZE - sizeof(decompSize)  # size_t
    inlen = inSize - LZMA_PROPS_SIZE - 8  # size_t

    props = [ord(data[i : i + 1]) for i in range(LZMA_PROPS_SIZE)]
    decompSize = struct.unpack("q", data[len(props) : len(props) + 8])[0]

    p = CLzmaDec(0, 0, 0, b"", 0, 0, b"", 0, 0, 0, 0, 0, 0, 0, 0, 0, b"")
    LzmaDec_AllocateProbs(p, props, len(props))
    p.dicBufSize = decompSize
    LzmaDec_InitDicAndState(p, True, True)
    LzmaDec_DecodeToDic(p, memoryview(data)[len(props) + 8 :], inlen, "LZMA_FINISH_ANY", "LZMA_STATUS_NOT_SPECIFIED")
    return p.dic
