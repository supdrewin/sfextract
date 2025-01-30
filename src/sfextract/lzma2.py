import struct
from dataclasses import dataclass

from sfextract.lzma1 import (
    LZMA_PROPS_SIZE,
    CLzmaDec,
    LzmaDec_AllocateProbs,
    LzmaDec_DecodeToDic,
    LzmaDec_InitDicAndState,
)

LZMA2_LCLP_MAX = 4


@dataclass
class CLzma2Dec:
    state: str
    control: int
    needInitLevel: int
    isExtraMode: bool
    pad: str
    packSize: int
    unpackSize: int
    decoder: CLzmaDec


def Lzma2Dec_UpdateState(p: CLzma2Dec, b):
    if p.state == "LZMA2_STATE_CONTROL":
        p.isExtraMode = False
        p.control = b
        if b == 0:
            return "LZMA2_STATE_FINISHED"
        if p.control & (1 << 7) == 0:
            if b == 1:
                p.needInitLevel = 0xC0
            elif b > 2 or p.needInitLevel == 0xE0:
                return "LZMA2_STATE_ERROR"
        else:
            if b < p.needInitLevel:
                return "LZMA2_STATE_ERROR"
            p.needInitLevel = 0
            p.unpackSize = (b & 0x1F) << 16
        return "LZMA2_STATE_UNPACK0"
    elif p.state == "LZMA2_STATE_UNPACK0":
        p.unpackSize |= b << 8
        return "LZMA2_STATE_UNPACK1"
    elif p.state == "LZMA2_STATE_UNPACK1":
        p.unpackSize |= b
        p.unpackSize += 1
        return "LZMA2_STATE_DATA" if p.control & (1 << 7) == 0 else "LZMA2_STATE_PACK0"
    elif p.state == "LZMA2_STATE_PACK0":
        p.packSize = b << 8
        return "LZMA2_STATE_PACK1"
    elif p.state == "LZMA2_STATE_PACK1":
        p.packSize |= b
        p.packSize += 1
        # if (p->packSize < 5) return LZMA2_STATE_ERROR;
        return "LZMA2_STATE_PROP" if p.control & 0x40 else "LZMA2_STATE_DATA"
    elif p.state == "LZMA2_STATE_PROP":
        if b >= (9 * 5 * 5):
            return "LZMA2_STATE_ERROR"
        lc = b % 9
        b = b // 9
        p.decoder.prop.pb = b // 5
        lp = b % 5
        if lc + lp > LZMA2_LCLP_MAX:
            return "LZMA2_STATE_ERROR"
        p.decoder.prop.lc = lc
        p.decoder.prop.lp = lp
        return "LZMA2_STATE_DATA"
    return "LZMA2_STATE_ERROR"


def LzmaDec_UpdateWithUncompressed(p: CLzmaDec, src: memoryview, size):
    p.dic += src[:size]
    p.dicPos += size
    if p.checkDicSize == 0 and p.prop.dicSize - p.processedPos <= size:
        p.checkDicSize = p.prop.dicSize
    p.processedPos += size


def Lzma2Dec_DecodeToDic(p: CLzma2Dec, dicLimit, src: memoryview, srcLen, finishMode):
    inSize = srcLen
    srcLen = 0
    status = "LZMA_STATUS_NOT_SPECIFIED"
    while p.state != "LZMA2_STATE_ERROR":
        if p.state == "LZMA2_STATE_FINISHED":
            return "SZ_OK", "LZMA_STATUS_FINISHED_WITH_MARK"
        dicPos = p.decoder.dicPos
        if dicPos == dicLimit and finishMode == "LZMA_FINISH_ANY":
            return "SZ_OK", "LZMA_STATUS_NOT_FINISHED"
        if p.state != "LZMA2_STATE_DATA" and p.state != "LZMA2_STATE_DATA_CONT":
            if srcLen == inSize:
                return "SZ_OK", "LZMA_STATUS_NEEDS_MORE_INPUT"
            p.state = Lzma2Dec_UpdateState(p, ord(bytes(src[srcLen : srcLen + 1])))
            srcLen += 1
            if dicPos == dicLimit and p.state != "LZMA2_STATE_FINISHED":
                break
            continue
        inCur = inSize - srcLen
        outCur = dicLimit - dicPos
        curFinishMode = "LZMA_FINISH_ANY"
        if outCur >= p.unpackSize:
            outCur = p.unpackSize
            curFinishMode = "LZMA_FINISH_END"
        if p.control & (1 << 7) == 0:
            if inCur == 0:
                return "SZ_OK", "LZMA_STATUS_NEEDS_MORE_INPUT"
            if p.state == "LZMA2_STATE_DATA":
                initDic = p.control == 1  # LZMA2_CONTROL_COPY_RESET_DIC = 1
                LzmaDec_InitDicAndState(p.decoder, initDic, False)
            if inCur > outCur:
                inCur = outCur
            if inCur == 0:
                break

            LzmaDec_UpdateWithUncompressed(p.decoder, src[srcLen:], inCur)
            srcLen += inCur
            p.unpackSize -= inCur
            p.state = "LZMA2_STATE_CONTROL" if p.unpackSize == 0 else "LZMA2_STATE_DATA_CONT"
        else:
            if p.state == "LZMA2_STATE_DATA":
                initDic = p.control >= 0xE0
                initState = p.control >= 0xA0
                LzmaDec_InitDicAndState(p.decoder, initDic, initState)
                p.state = "LZMA2_STATE_DATA_CONT"
            if inCur > p.packSize:
                inCur = p.packSize

            res, status = LzmaDec_DecodeToDic(p.decoder, src[srcLen:], inCur, curFinishMode, status)
            srcLen += inCur
            p.packSize -= inCur
            outCur = p.decoder.dicPos - dicPos
            p.unpackSize -= outCur

            if res != "SZ_OK":
                break

            if status == "LZMA_STATUS_NEEDS_MORE_INPUT":
                if p.packSize == 0:
                    break
                return "SZ_OK", "LZMA_STATUS_NEEDS_MORE_INPUT"

            if inCur == 0 and outCur == 0:
                # TODO: Always break for now, to be fixed when we can decode those chunked files
                break
                if status != "LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK" or p.unpackSize != 0 or p.packSize != 0:
                    break
                p.state = "LZMA2_STATE_CONTROL"

            status = "LZMA_STATUS_NOT_SPECIFIED"

    p.state = "LZMA2_STATE_ERROR"
    return "SZ_ERROR_DATA", "LZMA_STATUS_NOT_SPECIFIED"


def decompress(data):
    # Lzma2Decomp()
    inSize = len(data)
    # inlen = inSize - sizeof(prop) - sizeof(decompSize)  # size_t
    inlen = inSize - 1 - 8  # size_t

    prop = ord(data[:1])
    decompSize = struct.unpack("q", data[1:9])[0]  # size_t

    # Lzma2Decode()
    props = [0] * LZMA_PROPS_SIZE

    # Lzma2Dec_GetOldProps()
    if prop == 40:
        dicSize = 0xFFFFFFFF
    else:
        dicSize = (2 | (prop & 1)) << (prop // 2 + 11)
    props[0] = LZMA2_LCLP_MAX
    props[1] = dicSize
    props[2] = dicSize >> 8
    props[3] = dicSize >> 16
    props[4] = dicSize >> 24

    decoder = CLzmaDec(0, 0, 0, b"", 0, 0, b"", 0, 0, 0, 0, 0, 0, 0, 0, 0, b"")
    LzmaDec_AllocateProbs(decoder, props, len(props))
    decoder.dicBufSize = decompSize

    # Back to Lzma2Decode()
    decoder2 = CLzma2Dec("LZMA2_STATE_CONTROL", 0, 0xE0, False, 0, 0, 0, decoder)
    res, status = Lzma2Dec_DecodeToDic(decoder2, decoder.dicBufSize, memoryview(data)[9:], inlen, "LZMA_FINISH_ANY")
    return decoder2.decoder.dic
