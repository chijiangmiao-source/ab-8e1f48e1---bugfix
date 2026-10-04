"""ARIES-style recovery engine for on-board attitude-control parameter pages.

Pipeline (exactly the three ARIES phases):

1. Analysis  — start at the checkpoint record, walk forward to build the
   dirty-page table (DPT) and transaction table (ATT).
2. Redo      — start at the smallest recLSN in the DPT, repeat history for
   every update whose change is genuinely missing from the crashed page
   image (pageLSN < update LSN).
3. Undo      — loser transactions (no commit record by crash time) are
   rolled back in reverse-LSN order along each transaction's prevLSN
   chain; a page is rewritten only when the page-LSN condition holds
   (the page currently carries exactly the update being undone).

Only record types begin/update/commit/abort/end/checkpoint are accepted.
Every update carries its transaction predecessor (prevLSN), page number,
a half-open in-page interval [offset, offset+length) and equal-length
before/after byte strings.  Crashed page images carry their pageLSN.

Deliberately dependency-free (Python standard library only).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

PAGE_SIZE = 4096
MAX_PAGES = 48
MAX_RECORDS = 128

RECORD_TYPES = {"begin", "update", "commit", "abort", "end", "checkpoint"}
TERMINATORS = {"commit", "abort"}


class RecoveryError(ValueError):
    """Stable rejection: the recovery request is invalid and must not run.

    The optional *fingerprint* carries the semantic fingerprint of the
    structurally parsed input, so even inputs that later fail chain /
    lifecycle validation can be stably replayed across restarts.
    """

    def __init__(self, message: str, fingerprint: Optional[str] = None) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint


@dataclass
class Record:
    lsn: int
    kind: str
    xid: Optional[str]
    prev_lsn: Optional[int]
    page: Optional[int]
    offset: Optional[int]
    length: Optional[int]
    before: bytes
    after: bytes
    cp_txn: dict[str, Optional[int]] = field(default_factory=dict)
    cp_dirty: dict[int, int] = field(default_factory=dict)
    raw_index: int = 0


@dataclass
class PageState:
    page_no: int
    data: bytearray
    initial_data: bytes
    page_lsn: Optional[int]
    initial_lsn: Optional[int]
    initial_sha: str


def _hex_to_bytes(value: Any, field_name: str, expected_len: Optional[int] = None) -> bytes:
    """Decode a hex string; even length, bytes only."""
    if not isinstance(value, str):
        raise RecoveryError(f"{field_name} 必须是十六进制字符串")
    text = value[2:] if value.lower().startswith("0x") else value
    if text == "":
        raw = b""
    else:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise RecoveryError(f"{field_name} 不是合法的十六进制数据")
    if expected_len is not None and len(raw) != expected_len:
        raise RecoveryError(
            f"{field_name} 长度为 {len(raw)} 字节，应为 {expected_len} 字节"
        )
    return raw


def _as_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecoveryError(f"{field_name} 必须是整数")
    return value


def parse_record(raw: dict[str, Any], index: int) -> Record:
    """Parse and validate one user-supplied WAL record shape."""
    where = f"WAL[{index}]"
    if not isinstance(raw, dict):
        raise RecoveryError(f"{where} 必须是对象")

    lsn = _as_int(raw.get("lsn"), f"{where}.lsn")
    if lsn <= 0:
        raise RecoveryError(f"{where}.lsn 必须为正整数")

    kind = raw.get("type")
    if kind not in RECORD_TYPES:
        raise RecoveryError(
            f"{where}(LSN {lsn}) 记录类型 {kind!r} 非法，"
            "仅允许 begin/update/commit/abort/end/checkpoint"
        )

    rec = Record(
        lsn=lsn,
        kind=kind,
        xid=None,
        prev_lsn=None,
        page=None,
        offset=None,
        length=None,
        before=b"",
        after=b"",
        raw_index=index,
    )

    if kind == "checkpoint":
        txns = raw.get("transactions") or {}
        dirty = raw.get("dirtyPages") or {}
        if not isinstance(txns, dict) or not isinstance(dirty, dict):
            raise RecoveryError(f"{where}(LSN {lsn}) 检查点表必须为对象")
        for xid, last in txns.items():
            if not isinstance(xid, str) or not xid:
                raise RecoveryError(f"{where}(LSN {lsn}) 检查点事务标识非法")
            if last is not None:
                last = _as_int(last, f"{where} 事务 {xid} 的 lastLSN")
                if last <= 0:
                    raise RecoveryError(f"{where} 事务 {xid} 的 lastLSN 必须为正数")
            rec.cp_txn[xid] = last
        for page_no, rec_lsn in dirty.items():
            try:
                pno = int(page_no)
            except (TypeError, ValueError):
                raise RecoveryError(f"{where}(LSN {lsn}) 脏页号 {page_no!r} 非法")
            rlsn = _as_int(rec_lsn, f"{where}(LSN {lsn}) 脏页 {pno} 的 recLSN")
            if pno < 0 or rlsn <= 0:
                raise RecoveryError(f"{where}(LSN {lsn}) 脏页 {pno} 表项非法")
            rec.cp_dirty[pno] = rlsn
        return rec

    xid = raw.get("xid")
    if not isinstance(xid, str) or not xid:
        raise RecoveryError(f"{where}(LSN {lsn}) 缺少事务标识 xid")
    rec.xid = xid

    if kind == "begin":
        return rec

    # update / commit / abort / end all carry the predecessor link.
    if "prevLSN" not in raw or raw.get("prevLSN") is None:
        raise RecoveryError(f"{where}(LSN {lsn}, {kind}) 缺少事务前驱 prevLSN")
    prev = _as_int(raw["prevLSN"], f"{where}.prevLSN")
    if prev <= 0:
        raise RecoveryError(f"{where}(LSN {lsn}) prevLSN 必须为正整数（指向真实前驱记录）")
    rec.prev_lsn = prev

    if kind == "update":
        page_no = _as_int(raw.get("page"), f"{where}.page")
        if page_no < 0:
            raise RecoveryError(f"{where}(LSN {lsn}) 页号不能为负")
        offset = _as_int(raw.get("offset"), f"{where}.offset")
        if offset < 0:
            raise RecoveryError(f"{where}(LSN {lsn}) 页内偏移不能为负")
        before = _hex_to_bytes(raw.get("before"), f"{where}(LSN {lsn}).before")
        after = _hex_to_bytes(raw.get("after"), f"{where}(LSN {lsn}).after")
        if len(before) != len(after):
            raise RecoveryError(
                f"{where}(LSN {lsn}) before/after 必须等长"
                f"（{len(before)} != {len(after)}）"
            )
        length = len(before)
        if length == 0:
            raise RecoveryError(f"{where}(LSN {lsn}) 更新长度不能为 0")
        if offset + length > PAGE_SIZE:
            raise RecoveryError(
                f"{where}(LSN {lsn}) 半开区间 [{offset},{offset + length}) "
                f"越界（页大小 {PAGE_SIZE}）"
            )
        rec.page = page_no
        rec.offset = offset
        rec.length = length
        rec.before = before
        rec.after = after

    return rec


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canon_hex(raw: bytes) -> str:
    """Canonical spelling of byte data: lower-case hex, no 0x prefix."""
    return raw.hex()


def _canon_record(rec: Record) -> dict[str, Any]:
    """Canonical, semantics-only shape of one WAL record.

    Field spelling that does not change recovery semantics (JSON key
    ordering, hex case, an 0x prefix) is normalized away.
    """
    out: dict[str, Any] = {
        "lsn": rec.lsn,
        "type": rec.kind,
        "xid": rec.xid,
    }
    if rec.kind == "checkpoint":
        out["transactions"] = {x: rec.cp_txn[x] for x in sorted(rec.cp_txn)}
        out["dirtyPages"] = {str(p): rec.cp_dirty[p] for p in sorted(rec.cp_dirty)}
        return out
    if rec.prev_lsn is not None:
        out["prevLSN"] = rec.prev_lsn
    if rec.kind == "update":
        out.update(
            page=rec.page,
            offset=rec.offset,
            length=rec.length,
            before=_canon_hex(rec.before),
            after=_canon_hex(rec.after),
        )
    return out


def _canon_payload(pages: dict[int, PageState],
                   records: list[Record]) -> dict[str, Any]:
    """Deterministic representation of the whole recovery input.

    Independent of: JSON object key order, hex digit case / 0x prefix, and
    the order in which crashed page images are listed.  The stable audit
    identifier (the storage key) is deliberately excluded: the fingerprint
    identifies the recovery input itself (pages + WAL).
    """
    canon_pages = [
        {
            "page": pno,
            "pageLSN": pages[pno].initial_lsn,
            "data": _canon_hex(pages[pno].initial_data),
        }
        for pno in sorted(pages)
    ]
    return {
        "pages": canon_pages,
        "wal": [_canon_record(r) for r in records],
    }


def input_fingerprint(canon: Any) -> str:
    """Stable SHA-256 over the canonical recovery input."""
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return _sha256(blob)


def _validate_chain(records: list[Record], by_lsn: dict[int, Record], cp: Optional[Record]) -> None:
    """Global lifecycle + prevLSN chain validation in LSN order."""
    ended: set[str] = set()
    begun: set[str] = set()
    last_lsn: dict[str, int] = {}

    if cp is not None:
        for xid, last in cp.cp_txn.items():
            if last is None:
                # The transaction began before the supplied WAL window; a
                # begin record later in the window would be a duplicate begin.
                continue
            target = by_lsn.get(last)
            if target is None:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 事务 {xid} 的 lastLSN {last} "
                    "在 WAL 中不存在（断链）"
                )
            if target.lsn >= cp.lsn:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 事务 {xid} 的 lastLSN {last} "
                    "不能晚于检查点本身"
                )
            if target.xid != xid:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 事务 {xid} 的 lastLSN {last} 属于其他事务"
                )
        for pno, rlsn in cp.cp_dirty.items():
            target = by_lsn.get(rlsn)
            if target is None:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 脏页 {pno} 的 recLSN {rlsn} "
                    "在 WAL 中不存在（断链）"
                )
            if target.lsn >= cp.lsn:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 脏页 {pno} 的 recLSN {rlsn} "
                    "不能晚于检查点本身"
                )
            if target.kind != "update" or target.page != pno:
                raise RecoveryError(
                    f"检查点(LSN {cp.lsn}) 脏页 {pno} 的 recLSN {rlsn} 不是该页的 update"
                )

    # Transactions carried by the checkpoint have already begun; seed the
    # lifecycle set so a later begin for the same xid is rejected.
    for xid in cp.cp_txn if cp is not None else ():
        begun.add(xid)
        # lastLSN may be None for a txn whose records precede the window;
        # such an entry contributes no usable chain tail.
        if cp.cp_txn[xid] is not None:
            last_lsn[xid] = cp.cp_txn[xid]

    for rec in records:
        if rec.kind == "checkpoint":
            continue
        assert rec.xid is not None

        if rec.kind == "begin":
            if rec.xid in begun:
                # A begin before the checkpoint is the same transaction the
                # checkpoint table refers to — legitimate.  A second begin at
                # or after the checkpoint is a duplicate/reused xid.
                if cp is None or rec.lsn > cp.lsn:
                    raise RecoveryError(
                        f"事务 {rec.xid} 的 begin 重复（已结束/检查点事务不可复用标识）"
                    )
            begun.add(rec.xid)
            last_lsn[rec.xid] = rec.lsn
            continue

        # Every other record type needs a live, begun transaction.
        if rec.xid not in begun:
            raise RecoveryError(
                f"LSN {rec.lsn}({rec.kind}) 引用了未开始的事务 {rec.xid}"
            )
        if rec.xid in ended:
            raise RecoveryError(
                f"LSN {rec.lsn}({rec.kind}) 仍引用已结束事务 {rec.xid}（已写 end）"
            )

        prev = by_lsn.get(rec.prev_lsn)
        if prev is None:
            raise RecoveryError(
                f"LSN {rec.lsn} 的 prevLSN {rec.prev_lsn} 在 WAL 中不存在（断链）"
            )
        if prev.xid != rec.xid:
            raise RecoveryError(
                f"LSN {rec.lsn} 的前驱 {rec.prev_lsn} 属于事务 "
                f"{prev.xid}，而非 {rec.xid}（前驱链断裂）"
            )
        if rec.xid not in last_lsn:
            raise RecoveryError(
                f"LSN {rec.lsn} 的事务 {rec.xid} 在检查点中 lastLSN 为空"
                "（链尾位于所给 WAL 窗口之外），无法在窗口内验证其前驱链"
            )
        if last_lsn[rec.xid] != rec.prev_lsn:
            raise RecoveryError(
                f"LSN {rec.lsn} 的事务前驱链失序：事务 {rec.xid} 链尾为 "
                f"{last_lsn[rec.xid]}，记录却指向 {rec.prev_lsn}"
            )

        if rec.kind == "end":
            if prev.kind not in TERMINATORS:
                raise RecoveryError(
                    f"LSN {rec.lsn}(end) 的前驱 LSN {prev.lsn} 是 {prev.kind}，"
                    "end 必须紧跟 commit/abort"
                )
            ended.add(rec.xid)
        elif prev.kind in TERMINATORS:
            raise RecoveryError(
                f"LSN {rec.lsn}({rec.kind}) 把控制记录 LSN {prev.lsn}"
                f"({prev.kind}) 当作事务前驱（链非法，commit/abort 后只允许 end）"
            )

        last_lsn[rec.xid] = rec.lsn


def recover(payload: dict[str, Any]) -> dict[str, Any]:
    """Run analysis/redo/undo over the supplied pages + WAL.

    Returns a frozen verdict dictionary; raises RecoveryError on any
    broken chain, duplicate LSN, wrong before-image, out-of-range interval
    or reference to a transaction that already ended.
    """
    if not isinstance(payload, dict):
        raise RecoveryError("请求体必须为 JSON 对象")

    audit_id = payload.get("auditId")
    if not isinstance(audit_id, str) or not audit_id.strip():
        raise RecoveryError("缺少稳定审计标识 auditId")
    audit_id = audit_id.strip()
    if len(audit_id) > 128:
        raise RecoveryError("审计标识长度不能超过 128 字符")

    pages_raw = payload.get("pages", [])
    wal_raw = payload.get("wal", [])
    if not isinstance(pages_raw, list) or not isinstance(wal_raw, list):
        raise RecoveryError("pages 与 wal 必须为数组")
    if len(pages_raw) > MAX_PAGES:
        raise RecoveryError(f"初始页像至多 {MAX_PAGES} 个，收到 {len(pages_raw)}")
    if len(wal_raw) > MAX_RECORDS:
        raise RecoveryError(f"WAL 记录至多 {MAX_RECORDS} 条，收到 {len(wal_raw)}")
    if not pages_raw:
        raise RecoveryError("至少需要一个初始页像")

    # ---- parse pages -----------------------------------------------------
    pages: dict[int, PageState] = {}
    for i, p in enumerate(pages_raw):
        if not isinstance(p, dict):
            raise RecoveryError(f"pages[{i}] 必须是对象")
        page_no = _as_int(p.get("page"), f"pages[{i}].page")
        if page_no < 0:
            raise RecoveryError(f"pages[{i}] 页号不能为负")
        if page_no in pages:
            raise RecoveryError(f"页 {page_no} 的崩溃页像重复")
        data = _hex_to_bytes(p.get("data"), f"pages[{i}].data", PAGE_SIZE)
        pls = p.get("pageLSN")
        page_lsn: Optional[int] = None
        if pls is not None:
            page_lsn = _as_int(pls, f"pages[{i}].pageLSN")
            if page_lsn < 0:
                raise RecoveryError(f"pages[{i}] pageLSN 不能为负")
        pages[page_no] = PageState(
            page_no=page_no,
            data=bytearray(data),
            initial_data=data,
            page_lsn=page_lsn,
            initial_lsn=page_lsn,
            initial_sha=_sha256(data),
        )

    # ---- parse records ---------------------------------------------------
    records: list[Record] = [parse_record(r, i) for i, r in enumerate(wal_raw)]

    # Semantic fingerprint of the structurally parsed recovery input.  It is
    # computed before ordering/chain validation so even inputs that fail
    # those checks carry a stable fingerprint for replay, and it is part of
    # every frozen success verdict.  Field spelling that carries no business
    # meaning (JSON key order, hex-letter case, an 0x prefix, the order the
    # crashed page images are listed) is normalized away.
    canon = _canon_payload(pages, records)
    fingerprint = input_fingerprint(canon)

    by_lsn: dict[int, Record] = {}
    for rec in records:
        if rec.lsn in by_lsn:
            raise RecoveryError(f"检测到重复 LSN {rec.lsn}", fingerprint)
        by_lsn[rec.lsn] = rec

    for a, b in zip(records, records[1:]):
        if b.lsn <= a.lsn:
            raise RecoveryError(
                f"WAL 必须严格按 LSN 升序排列：LSN {a.lsn} 之后出现 {b.lsn}",
                fingerprint,
            )

    checkpoints = [r for r in records if r.kind == "checkpoint"]
    if len(checkpoints) > 1:
        raise RecoveryError("至多允许一条 checkpoint 记录", fingerprint)
    cp = checkpoints[0] if checkpoints else None
    try:
        _validate_chain(records, by_lsn, cp)
    except RecoveryError as exc:
        if exc.fingerprint is None:
            exc.fingerprint = fingerprint
        raise

    trace: list[dict[str, Any]] = []

    # ================= ANALYSIS ==========================================
    dpt: dict[int, int] = {}                       # page -> recLSN
    att: dict[str, dict[str, Any]] = {}            # xid -> {status, lastLSN}

    start_index = 0
    if cp is not None:
        start_index = records.index(cp)
        for pno, rlsn in cp.cp_dirty.items():
            dpt[pno] = rlsn
        for xid, last in cp.cp_txn.items():
            att[xid] = {"status": "active", "lastLSN": last}
        trace.append(
            {
                "phase": "analysis",
                "lsn": cp.lsn,
                "type": "checkpoint",
                "xid": None,
                "page": None,
                "criterion": "分析从 checkpoint 开始",
                "decision": (
                    f"装入事务表 {sorted(cp.cp_txn) or '∅'}，"
                    f"脏页表 {{ {', '.join(f'{p}:{l}' for p, l in sorted(dpt.items()))} }}"
                ),
                "pageLSNBefore": None,
                "pageLSNAfter": None,
                "changed": False,
            }
        )

    for rec in records[start_index:]:
        if rec.kind == "checkpoint":
            continue
        assert rec.xid is not None
        note = ""
        if rec.kind == "begin":
            att[rec.xid] = {"status": "active", "lastLSN": rec.lsn}
            note = f"新建事务表项 status=active, lastLSN={rec.lsn}"
        elif rec.kind == "update":
            entry = att.setdefault(rec.xid, {"status": "active", "lastLSN": None})
            before_last = entry["lastLSN"]
            entry["lastLSN"] = rec.lsn
            if rec.page not in dpt:
                dpt[rec.page] = rec.lsn
                dpt_note = f"页 {rec.page} 首次变脏→DPT.recLSN={rec.lsn}"
            else:
                dpt_note = f"页 {rec.page} 已在 DPT(recLSN={dpt[rec.page]})，recLSN 不变"
            note = (
                f"ATT: lastLSN {before_last}→{rec.lsn}（沿 prevLSN={rec.prev_lsn}）；{dpt_note}"
            )
        elif rec.kind in TERMINATORS:
            entry = att.setdefault(rec.xid, {"status": "active", "lastLSN": None})
            old_status = entry["status"]
            entry["status"] = "committed" if rec.kind == "commit" else "aborted"
            entry["lastLSN"] = rec.lsn
            note = f"ATT: status {old_status}→{entry['status']}, lastLSN→{rec.lsn}"
        else:  # end
            entry = att.setdefault(rec.xid, {"status": "active", "lastLSN": None})
            entry["lastLSN"] = rec.lsn
            if rec.xid in att and entry["status"] in TERMINATORS:
                note = f"事务已 {entry['status']} 且收到 end → 从 ATT 移除"
                del att[rec.xid]
            else:
                note = "收到 end 但无 commit/abort（异常，前面的校验已拦截）"
        trace.append(
            {
                "phase": "analysis",
                "lsn": rec.lsn,
                "type": rec.kind,
                "xid": rec.xid,
                "page": rec.page,
                "criterion": f"分析归属：记录属于事务 {rec.xid}",
                "decision": note,
                "pageLSNBefore": None,
                "pageLSNAfter": None,
                "changed": False,
            }
        )

    # Losers: still resident in ATT with no commit record.  An aborted
    # transaction whose end never reached disk is also rolled back here.
    losers = {x: e for x, e in att.items() if e["status"] != "committed"}

    # ================= REDO ==============================================
    redo_start = min(dpt.values()) if dpt else None

    def current_page(page_no: int) -> PageState:
        if page_no not in pages:
            # An update touches a page whose crashed image was not supplied:
            # treat it as an untouched zero page (nothing ever reached disk).
            zeros = bytearray(PAGE_SIZE)
            data = bytes(zeros)
            pages[page_no] = PageState(
                page_no=page_no,
                data=zeros,
                initial_data=data,
                page_lsn=None,
                initial_lsn=None,
                initial_sha=_sha256(data),
            )
        return pages[page_no]

    if redo_start is not None:
        trace.append(
            {
                "phase": "redo",
                "lsn": None,
                "type": "redo-start",
                "xid": None,
                "page": None,
                "criterion": f"重做起点 = DPT 中最小 recLSN = {redo_start}",
                "decision": f"DPT {{ {', '.join(f'{p}:{l}' for p, l in sorted(dpt.items()))} }}",
                "pageLSNBefore": None,
                "pageLSNAfter": None,
                "changed": False,
            }
        )

    redone = 0
    for rec in records:
        if rec.kind != "update" or redo_start is None or rec.lsn < redo_start:
            continue
        st = current_page(rec.page)
        before_lsn = st.page_lsn
        already = before_lsn is not None and before_lsn >= rec.lsn
        interval = bytes(st.data[rec.offset : rec.offset + rec.length])

        if already:
            criterion = (
                f"重做判据：pageLSN={before_lsn} ≥ LSN {rec.lsn} → "
                "该更新已落盘，不重做"
            )
            decision = "跳过：崩溃页像已含此更新"
            changed = False
        elif interval == rec.after:
            criterion = (
                f"重做判据：pageLSN={'无' if before_lsn is None else before_lsn} "
                f"< LSN {rec.lsn}，但区间字节已等于 after（幂等）→ 不写页"
            )
            decision = "跳过：页内字节已是 after 镜像"
            changed = False
        elif interval == rec.before:
            st.data[rec.offset : rec.offset + rec.length] = rec.after
            st.page_lsn = rec.lsn
            changed = True
            redone += 1
            criterion = (
                f"重做判据：pageLSN={'无' if before_lsn is None else before_lsn} "
                f"< LSN {rec.lsn} 且区间等于 before → 确有缺失，重做"
            )
            decision = (
                f"重做 [{rec.offset},{rec.offset + rec.length})：before→after，"
                f"pageLSN {'无' if before_lsn is None else before_lsn}→{rec.lsn}"
            )
        else:
            raise RecoveryError(
                f"重做 LSN {rec.lsn}（事务 {rec.xid}，页 {rec.page}）时，"
                f"区间 [{rec.offset},{rec.offset + rec.length}) 当前字节既非 before 也非 after"
                " —— 错误前像，稳定拒绝",
                fingerprint,
            )

        trace.append(
            {
                "phase": "redo",
                "lsn": rec.lsn,
                "type": "update",
                "xid": rec.xid,
                "page": rec.page,
                "criterion": criterion,
                "decision": decision,
                "pageLSNBefore": before_lsn,
                "pageLSNAfter": st.page_lsn,
                "changed": changed,
                "offset": rec.offset,
                "length": rec.length,
            }
        )

    # ================= UNDO ==============================================
    # After redo every WAL update is present in the (in-memory) page images,
    # so no page remains dirty relative to the log: the DPT is empty at the
    # end of restart (ARIES writes a checkpoint after undo; the DPT state is
    # reported in the frozen verdict).
    dpt.clear()

    # ARIES undo list: highest LSN first across all loser chains.
    undo_stack = sorted(
        (e["lastLSN"] for e in losers.values() if e["lastLSN"] is not None),
        reverse=True,
    )
    trace.append(
        {
            "phase": "undo",
            "lsn": None,
            "type": "undo-start",
            "xid": None,
            "page": None,
            "criterion": "失败事务 = 崩溃时仍在 ATT 且无 commit 记录者；沿各自 prevLSN 链逆序撤销",
            "decision": f"失败者 {sorted(losers)}，初始撤销栈（按 LSN 逆序）{undo_stack}",
            "pageLSNBefore": None,
            "pageLSNAfter": None,
            "changed": False,
        }
    )

    undone = 0
    while undo_stack:
        lsn = undo_stack.pop(0)
        rec = by_lsn.get(lsn)
        if rec is None:
            raise RecoveryError(f"撤销链遇到不存在的 LSN {lsn}（断链）", fingerprint)
        if rec.kind != "update":
            if rec.kind == "begin":
                # Reached the transaction's begin: this chain ends.
                trace.append(
                    {
                        "phase": "undo",
                        "lsn": rec.lsn,
                        "type": rec.kind,
                        "xid": rec.xid,
                        "page": rec.page,
                        "criterion": "前驱链回溯到 begin，该事务撤销链结束",
                        "decision": "链终止",
                        "pageLSNBefore": None,
                        "pageLSNAfter": None,
                        "changed": False,
                    }
                )
                continue
            # An abort record without a following end (crash in between):
            # keep walking its prevLSN chain to reach the updates.
            trace.append(
                {
                    "phase": "undo",
                    "lsn": rec.lsn,
                    "type": rec.kind,
                    "xid": rec.xid,
                    "page": rec.page,
                    "criterion": f"失败事务沿 {rec.kind} 记录的 prevLSN={rec.prev_lsn} 继续回溯",
                    "decision": "控制记录，继续沿前驱链寻找 update",
                    "pageLSNBefore": None,
                    "pageLSNAfter": None,
                    "changed": False,
                }
            )
            if rec.prev_lsn:
                undo_stack.append(rec.prev_lsn)
                undo_stack.sort(reverse=True)
            continue

        st = current_page(rec.page)
        before_lsn = st.page_lsn
        if st.page_lsn != rec.lsn:
            raise RecoveryError(
                f"撤销 LSN {rec.lsn}（事务 {rec.xid}，页 {rec.page}）时页 LSN 条件不满足："
                f"当前 pageLSN={st.page_lsn}，期望 {rec.lsn}（只在条件满足时改写页像）",
                fingerprint,
            )
        interval = bytes(st.data[rec.offset : rec.offset + rec.length])
        if interval != rec.after:
            raise RecoveryError(
                f"撤销 LSN {rec.lsn}（事务 {rec.xid}，页 {rec.page}）时，"
                f"区间 [{rec.offset},{rec.offset + rec.length}) 当前字节不是 after 镜像"
                " —— 错误前像，稳定拒绝",
                fingerprint,
            )
        st.data[rec.offset : rec.offset + rec.length] = rec.before
        st.page_lsn = rec.prev_lsn if rec.prev_lsn else None
        undone += 1
        trace.append(
            {
                "phase": "undo",
                "lsn": rec.lsn,
                "type": "update",
                "xid": rec.xid,
                "page": rec.page,
                "criterion": (
                    f"撤销判据：pageLSN={before_lsn} == 撤销 LSN {rec.lsn} "
                    "→ 页 LSN 条件满足，逆序沿 prevLSN 链回写 before"
                ),
                "decision": (
                    f"撤销 [{rec.offset},{rec.offset + rec.length})：after→before，"
                    f"pageLSN {before_lsn}→{rec.prev_lsn}，下一跳 {rec.prev_lsn}"
                ),
                "pageLSNBefore": before_lsn,
                "pageLSNAfter": st.page_lsn,
                "changed": True,
                "offset": rec.offset,
                "length": rec.length,
            }
        )
        undo_stack.append(rec.prev_lsn)
        undo_stack.sort(reverse=True)

    # ================= frozen verdict ====================================
    page_summary = []
    for pno in sorted(pages):
        st = pages[pno]
        final = bytes(st.data)
        page_summary.append(
            {
                "page": pno,
                "pageLSNBefore": st.initial_lsn,
                "pageLSNAfter": st.page_lsn,
                "sha256Before": st.initial_sha,
                "sha256After": _sha256(final),
                "changed": final != st.initial_data,
                "data": final.hex(),
            }
        )

    committed = sorted({r.xid for r in records if r.kind == "commit"})
    aborted = sorted({r.xid for r in records if r.kind == "abort"})

    return {
        "auditId": audit_id,
        "inputFingerprint": fingerprint,
        "committedTransactions": committed,
        "abortedTransactions": aborted,
        "loserTransactions": sorted(losers),
        "redoStartLSN": redo_start,
        "redone": redone,
        "undone": undone,
        "dirtyPageTableAtEnd": dpt,
        "pages": page_summary,
        "trace": trace,
    }
