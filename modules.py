from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping, Sequence, Iterable, Any, Hashable, List
import numpy as np
import pandas as pd
from collections import defaultdict


@dataclass
class CoverageMatrix:
    """
    Generic N-dimensional counter with named axes.
    Example axes = {"access": ["read", "write"],
                    "arch"  : range(1, 33),
                    "phys"  : range(1, 257)}
    """
    axes: Mapping[str, Sequence[Hashable]]
    _hits: np.ndarray = field(init=False, repr=False)

    def __post_init__(self):
        # Keep axis order stable for predictable tuple indexing
        self._axis_names = tuple(self.axes.keys())
        self._axis_sizes = tuple(len(self.axes[name]) for name in self._axis_names)
        self._label2index = {
            name: {label: i for i, label in enumerate(labels)}
            for name, labels in self.axes.items()
        }
        self._hits = np.zeros(self._axis_sizes, dtype=np.uint64)

    # ------------------------------------------------------------------ counters
    def incr(self, **labels: Hashable):
        """Increment a single event, e.g. incr(entry=5, fu=2)."""
        idx = tuple(self._label2index[k][labels[k]] for k in self._axis_names)
        self._hits[idx] += 1

    # ------------------------------------------------------------------ queries
    def total(self, **constraints: Iterable[Hashable] | Hashable) -> int:
        """
        Sum over an arbitrary sub-cube:
        total(entry=[0,1,2], fu='ALL')   ??C> rows 0-2, all columns
        total()                           ??C> grand total
        """
        slices = []
        for ax in self._axis_names:
            if ax not in constraints or constraints[ax] in (None, 'ALL'):
                slices.append(slice(None))
            else:
                labels = constraints[ax]
                if not isinstance(labels, Iterable) or isinstance(labels, str):
                    labels = [labels]
                slices.append([self._label2index[ax][lbl] for lbl in labels])
        return int(self._hits[tuple(slices)].sum())

    # ------------------------------------------------------------------ utilities
    def coverage_ratio(self) -> float:
        return float((self._hits > 0).sum() / self._hits.size)

    def to_frame(self, stack: bool = True) -> pd.DataFrame:
        """Return a DataFrame; stack=False keeps N-dims as columns."""
        idx = pd.MultiIndex.from_product(self.axes.values(), names=self._axis_names)
        flat = self._hits.reshape(-1)
        df = pd.DataFrame({"hits": flat}, index=idx)
        return df.reset_index() if stack else df.unstack()

    # ------------------------------------------------------------------ queries
    def ratio(self, **constraints: Iterable[Hashable] | Hashable) -> float:
        """
        coverage *ratio* (0.0-C1.0) for any sub-cube.
        Examples
        --------
        cm.ratio(access="write")          # how many write-access rows got hits?
        cm.ratio(set=[0,1,2], way='ALL')  # first three sets, both ways
        cm.ratio()                        # grand coverage (same as .coverage_ratio())
        """
        # --- 1.  Build the slice tuple exactly like `total()` ------------------
        slices = []
        for ax in self._axis_names:
            if ax not in constraints or constraints[ax] in (None, "ALL"):
                slices.append(slice(None))
            else:
                labels = constraints[ax]
                if not isinstance(labels, Iterable) or isinstance(labels, str):
                    labels = [labels]
                slices.append([self._label2index[ax][lbl] for lbl in labels])

        # --- 2.  Extract the sub-array and compute ratio -----------------------
        sub = self._hits[tuple(slices)]
        covered = (sub > 0).sum()  # cells that saw at least one event
        total = sub.size  # all cells in that sub-cube
        return float(covered / total) if total else 0.0


# ----------------------------------------------------------------------
# Local 2-bit saturating counter table
# ----------------------------------------------------------------------
class BPT_local:
    """
    Local branch-predictor table with 2-bit (or N-bit) saturating counters.

    Public interface unchanged:
        bp = BPT_local(numBits=2, numEntries=1024)
        bp.log_event(row=7, old_val=1, new_val=2)
        cov = bp.coverage_report("bpt_local.csv")
    """

    def __init__(self, numBits: int = 2, numEntries: int = 1024):
        self.numBits     = numBits
        self.numEntries  = numEntries
        self.max_val     = (1 << numBits) - 1

        # Build the transition axis once
        self._trans_labels: List[str] = []
        for j in range(self.max_val + 1):                    # up-count
            self._trans_labels.append(f"{j}_to_{min(j+1, self.max_val)}")
        for j in range(self.max_val, -1, -1):                # down-count
            self._trans_labels.append(f"{j}_to_{max(j-1, 0)}")

        self._cm = CoverageMatrix(
            axes={
                "row"  : range(numEntries),
                "tran" : self._trans_labels
            }
        )
        self.N_EVENTS = self._cm._hits.size

    # ------------------------------------------------------------------ API
    def log_event(self, row: int, old_val: int, new_val: int):
        row = int(row)
        old_val = int(old_val)
        new_val = int(new_val)
        self._cm.incr(row=row, tran=f"{old_val}_to_{new_val}")

    def coverage_report(self, path: str | None = None) -> float:
        # coverage ratio
        cov = self._cm.coverage_ratio()

        # build the DataFrame in exactly the same shape as before
        df = pd.DataFrame(
            self._cm._hits,                      # shape = (rows , transitions)
            index=[f"row_{i}" for i in range(self.numEntries)],
            columns=self._trans_labels
        )
        if path:
            df.to_csv(path)
        return cov

    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for ????all????)."""
        return int(self._cm.total(**constraints))


# ----------------------------------------------------------------------
# Bi-mode branch predictor (Not-taken, Taken, Choice tables)
# ----------------------------------------------------------------------
class BPT_bi_mode:
    """
    Three independent 2-bit tables: not-taken, taken, choice.
    Public interface identical to your original:
        bp = BPT_bi_mode(numBits=2, numEntries=1024)
        bp.log_event("taken", row=15, old_val=0, new_val=1)
        cov = bp.coverage_report("bpt_bimode.csv")
    """

    _tables = ("taken", "not_taken", "choice")

    def __init__(self, numBits: int = 2, numEntries: int = 1024):
        self.numBits    = numBits
        self.numEntries = numEntries
        self.max_val    = (1 << numBits) - 1

        # shared transition axis
        self._trans_labels: List[str] = []
        for j in range(self.max_val + 1):
            self._trans_labels.append(f"{j}_to_{min(j+1, self.max_val)}")
        for j in range(self.max_val, -1, -1):
            self._trans_labels.append(f"{j}_to_{max(j-1, 0)}")

        self._cm = CoverageMatrix(
            axes={
                "table": self._tables,
                "row"  : range(numEntries),
                "tran" : self._trans_labels
            }
        )
        self.N_EVENTS = self._cm._hits.size

    # ------------------------------------------------------------------ API
    # def log_event(self, table: str, row: int, old_val: int, new_val: int):
    def log_event(self, table, row, old_val, new_val):
        row = int(row)
        if table not in self._tables:
            raise ValueError(f"table must be one of {self._tables}")
        self._cm.incr(table=table, row=row, tran=f"{old_val}_to_{new_val}")

    def coverage_report(self, path: str | None = None) -> float:
        cov = self._cm.coverage_ratio()

        # Re-create the flat CSV layout:   taken_row_0 ???? taken_row_N-1
        #                                 not_taken_row_0 ???? choice_row_N-1
        frames = []
        for tbl in self._tables:
            tbl_idx = self._cm._label2index["table"][tbl]
            sub_hits = self._cm._hits[tbl_idx, :, :]          # shape (rows, trans)
            frames.append(
                pd.DataFrame(
                    sub_hits,
                    index=[f"{tbl}_row_{i}" for i in range(self.numEntries)],
                    columns=self._trans_labels
                )
            )
        df = pd.concat(frames)

        if path:
            df.to_csv(path)
        return cov


    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for ????all????)."""
        return int(self._cm.total(**constraints))


# ---------------------------------------------------------------------------
#  Register-Mapping Table
# ---------------------------------------------------------------------------
class register_mapping_table:
    """
    Public interface identical to the old class:
        rmt = register_mapping_table()
        rmt.log_event('r', 5, 42)
        cov = rmt.coverage_report("rmt.csv")
    """

    def __init__(self, n_arch_reg: int = 32, n_phys_reg: int = 256):
        self.N_ARCH_REG = n_arch_reg
        self.N_PHYS_REG = n_phys_reg

        self._cm = CoverageMatrix(
            axes={
                "access": ["read", "write"],
                "arch":   range(1, n_arch_reg),
                "phys":   range(1, n_phys_reg),
            }
        )
        self.N_EVENTS = self._cm._hits.size  # keep attr for callers

    # ------------------------------------------------------------------ API
    def log_event(self, access_type: str, arch_reg, phys_reg):
        arch_reg = int(arch_reg)
        phys_reg = int(phys_reg)
        if arch_reg == 0 or phys_reg == 0:
            return
        if access_type not in ("r", "w"):
            raise ValueError("access_type must be 'r' or 'w'")
        self._cm.incr(access="read" if access_type == "r" else "write",
                      arch=arch_reg,
                      phys=phys_reg)

    def coverage_report(self, path: str | None = None) -> float:
        cov = self._cm.coverage_ratio()

        # Build same CSV: rows = arch-read/write, cols = phys registers
        rows = ([f"arch-{i}-read"  for i in range(1, self.N_ARCH_REG)] +
                [f"arch-{i}-write" for i in range(1, self.N_ARCH_REG)])
        df_read  = pd.DataFrame(self._cm._hits[0, :, :],  # access index 0 = read
                                index=rows[: self.N_ARCH_REG-1],
                                columns=[f"phys-{j}" for j in range(1, self.N_PHYS_REG)])
        df_write = pd.DataFrame(self._cm._hits[1, :, :],  # access index 1 = write
                                index=rows[self.N_ARCH_REG-1 :],
                                columns=df_read.columns)
        df = pd.concat([df_read, df_write])
        if path:
            df.to_csv(path)
        return cov


    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for ????all????)."""
        return int(self._cm.total(**constraints))


# ---------------------------------------------------------------------------
#  Issue-Queue
# ---------------------------------------------------------------------------
class issue_queue:
    """
    iq = issue_queue(32, 8)
    iq.log_issue_event(4, 2)
    iq.coverage_report("iq.csv")
    """

    def __init__(self, num_entry: int, num_fu: int):
        self.num_entry = num_entry
        self.num_fu    = num_fu

        self._cm = CoverageMatrix(
            axes={"entry": range(num_entry), "fu": range(num_fu)}
        )
        self.N_EVENTS       = self._cm._hits.size
        self.undefined_events: list[str] = []
        self.total_issue    = 0

        # run-time state tracking (unchanged)
        self.last_update_tick = "-1"
        self.contents = defaultdict(lambda: ["-" for _ in range(self.num_entry)])

    # ---------------- state-tracking helpers (unchanged) ---------------
    def add_value(self, tick, entry_id, content):
        entry_id = int(entry_id)
        if tick in self.contents:
            self.contents[tick][entry_id] = content
        else:
            if self.last_update_tick != "-1":
                self.contents[tick] = list(self.contents[self.last_update_tick])
            self.contents[tick][entry_id] = content
        self.last_update_tick = tick

    def remove_value(self, tick, entry_id):
        entry_id = int(entry_id)
        if tick in self.contents:
            self.contents[tick][entry_id] = "-"
        else:
            if self.last_update_tick != "-1":
                self.contents[tick] = list(self.contents[self.last_update_tick])
            self.contents[tick][entry_id] = "-"
        self.last_update_tick = tick

    def save_content_history(self, path: str):
        col_names = [f"entry_{i}" for i in range(self.num_entry)]
        df = pd.DataFrame.from_dict(self.contents, orient="index", columns=col_names).T
        df.to_csv(path)

    # ------------------------------------------------------------------ API
    def log_issue_event(self, entry_id, fu_id):
        entry_id = int(entry_id)
        fu_id = int(fu_id)
        try:
            self._cm.incr(entry=entry_id, fu=fu_id)
        except KeyError:
            self.undefined_events.append(f"issue_entry_{entry_id}_to_fu_{fu_id}")
        self.total_issue += 1

    def coverage_report(self, path: str | None = None) -> float:
        cov = self._cm.coverage_ratio()

        df = pd.DataFrame(self._cm._hits,
                          index=[f"entry-{i}" for i in range(self.num_entry)],
                          columns=[f"fu-{j}" for j in range(self.num_fu)])
        if path:
            df.to_csv(path)

        print(f"Total number of issues: {self.total_issue}")
        return cov


    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for ????all????)."""
        return int(self._cm.total(**constraints))


# ---------------------------------------------------------------------------
#  Reorder-Buffer (ROB)
# ---------------------------------------------------------------------------
class ROB:
    """
    """
    def __init__(self, num_entry: int):
        self.num_entry = num_entry

        # 1) per-entry events (insert, graduate, squash, match)
        self._cm_ev = CoverageMatrix(
            axes={
                "kind": ["insert", "graduate", "squash", "match"],
                "entry": range(num_entry)
            }
        )

        # 2) combination of head & tail pointers
        self._cm_comb = CoverageMatrix(
            axes={"head": range(num_entry), "tail": range(num_entry)}
        )

        # 3) #-instructions resident in ROB (0 ???? N)
        self._cm_ninst = CoverageMatrix(axes={"num": range(num_entry + 1)})

        self.N_EVENTS = (self._cm_ev._hits.size +
                         self._cm_comb._hits.size +
                         self._cm_ninst._hits.size)

        # additional runtime tracking
        self.last_update_tick = "-1"
        self.contents = defaultdict(lambda: ["-" for _ in range(self.num_entry)])
        self.max_num_instr = 0

    # -------------- state-tracking helpers (unchanged) -----------------
    def add_value(self, tick, entry_id, content):
        entry_id = int(entry_id)
        if tick in self.contents:
            self.contents[tick][entry_id] = content
        else:
            if self.last_update_tick != "-1":
                self.contents[tick] = list(self.contents[self.last_update_tick])
            self.contents[tick][entry_id] = content
        self.last_update_tick = tick

    def remove_value(self, tick, entry_id):
        entry_id = int(entry_id)
        if tick in self.contents:
            self.contents[tick][entry_id] = "-"
        else:
            if self.last_update_tick != "-1":
                self.contents[tick] = list(self.contents[self.last_update_tick])
            else:
                print("remove happen before add")
            self.contents[tick][entry_id] = "-"
        self.last_update_tick = tick

    def save_content_history(self, path: str):
        col_names = [f"entry_{i}" for i in range(self.num_entry)]
        df = pd.DataFrame.from_dict(self.contents, orient="index",
                                    columns=col_names).T
        df.to_csv(path)

    # ------------------------------------------------------------------ API
    def log_event(self, opt_name: str, entry_id, head, tail, numInsts):
        entry_id = int(entry_id)  # make sure it's an int
        head = int(head)
        tail = int(tail)
        numInsts = int(numInsts)

        kind = opt_name.split("_")[-1]  # insert | graduate | squash
        self._cm_ev.incr(kind=kind, entry=entry_id)
        self._cm_comb.incr(head=head, tail=tail)
        self._cm_ninst.incr(num=numInsts)

    def log_event_match(self, entry_id):
        self._cm_ev.incr(kind="match", entry=int(entry_id))

    def coverage_report(self, path: str | None = None) -> int:
        """
        Behaviour unchanged: returns the maximum number of in-flight
        instructions ever observed, and (optionally) writes the same CSV
        layout as the original numInsts table.
        """
        # extract numInsts row
        hit_row = self._cm_ninst._hits.astype(int)  # shape (N+1,)
        self.max_num_instr = int((hit_row > 0).nonzero()[0].max(initial=0))
        print(f"Max num: {self.max_num_instr}")

        if path:
            df = pd.DataFrame([hit_row],
                              index=["num_hits"],
                              columns=[f"numInsts_{i}"
                                       for i in range(self.num_entry + 1)])
            df.to_csv(path)

        return self.max_num_instr


    # def total(self, **constraints) -> int:
    #     """Sum counts that meet the given constraints (leave axis absent/None for ????all????)."""
    #     return int(self._cm.total(**constraints))


# ---------------------------------------------------------------------------
#  Store-Set Unit (SSIT + LFST)
# ---------------------------------------------------------------------------
class store_set_v0:
    """
    ss = store_set()
    ss.log_event("ssit", "read_invalid", 5)
    ss.coverage_report("storeset.csv")
    """

    _ops = ["read_invalid", "read_valid", "write_invalid",
            "write_valid", "invalidate"]

    def __init__(self, size_SSIT: int = 1024, size_LFST: int = 1024):
        self.size_SSIT = size_SSIT
        self.size_LFST = size_LFST

        self._cm = CoverageMatrix(
            axes={
                "table": ["ssit", "lfst"],
                "row":   range(max(size_SSIT, size_LFST)),
                "op":    self._ops,
            }
        )
        self.N_EVENTS = self._cm._hits.size

    # ------------------------------------------------------------------ API
    def log_event(self, table_name, operation, row_id):
        row_id = int(row_id)
        if table_name not in ("ssit", "lfst"):
            raise ValueError("table_name must be 'ssit' or 'lfst'")
        if operation not in self._ops:
            raise ValueError(f"operation must be one of {self._ops}")
        self._cm.incr(table=table_name, row=row_id, op=operation)

    def coverage_report(self, path: str | None = None) -> float:
        cov = self._cm.coverage_ratio()

        # build identical CSV: rows = ssit_row_i + lfst_row_i, cols = ops
        col_labels = self._ops
        rows = ([f"ssit_row_{i}" for i in range(self.size_SSIT)] +
                [f"lfst_row_{i}" for i in range(self.size_LFST)])
        table_hits = []

        for i in range(self.size_SSIT):
            table_hits.append(self._cm._hits[0, i, :].tolist())  # ssit index 0
        for i in range(self.size_LFST):
            table_hits.append(self._cm._hits[1, i, :].tolist())  # lfst index 1

        if path:
            pd.DataFrame(table_hits, index=rows, columns=col_labels).to_csv(path)
        return cov

    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for all)."""
        return int(self._cm.total(**constraints))


class store_set:
    """
    ss = StoreSet()
    ss.log_event("ssit", "read_invalid",  5)
    ss.log_event("lfst", "invalidate",    8)
    ss.coverage_report("storeset.csv")
    """

    _ops = ["read_invalid", "read_valid",
            "write_invalid", "write_valid",
            "invalidate"]                    # 'invalidate' applies **only** to LFST

    def __init__(self, size_SSIT: int = 1024, size_LFST: int = 1024):
        self.size_SSIT, self.size_LFST = size_SSIT, size_LFST

        # ------------------- two clean matrices ----------------------------
        self._cm_ssit = CoverageMatrix(
            axes={
                "row": range(size_SSIT),
                "op":  self._ops[:-1]     # 4 ops, no 'invalidate'
            }
        )
        self._cm_lfst = CoverageMatrix(
            axes={
                "row": range(size_LFST),
                "op":  self._ops          # 5 ops, incl. 'invalidate'
            }
        )

    def _select_cm(self, table: str) -> CoverageMatrix:
        return self._cm_ssit if table == "ssit" else self._cm_lfst


    def log_event(self, table_name: str, operation: str, row_id: int):
        if table_name not in ("ssit", "lfst"):
            raise ValueError("table_name must be 'ssit' or 'lfst'")
        if operation not in self._ops:
            raise ValueError(f"operation must be one of {self._ops}")

        row_id = int(row_id)
        cm = self._select_cm(table_name)
        if row_id >= cm.axes["row"][-1] + 1:
            raise IndexError(f"row_id {row_id} out of range for {table_name}")
        if table_name == "ssit" and operation == "invalidate":
            raise ValueError("'invalidate' never occurs on SSIT")

        cm.incr(row=row_id, op=operation)


    def coverage_ratio(self) -> float:
        """Overall legal-cells coverage ratio (0.0??C1.0)."""
        covered = (self._cm_ssit._hits > 0).sum() + (self._cm_lfst._hits > 0).sum()
        total   = self._cm_ssit._hits.size      + self._cm_lfst._hits.size
        return covered / total if total else 0.0


    def coverage_report(self, path: str | None = None) -> float:
        """
        Generate a CSV with ?one row per table row?
        and ?one column per op present for that table?.
        """
        # ---- SSIT part ----------------------------------------------------
        rows_ssit = [f"ssit_row_{i}" for i in range(self.size_SSIT)]
        df_ssit   = pd.DataFrame(self._cm_ssit._hits,
                                 index=rows_ssit,
                                 columns=self._ops[:-1])

        # ---- LFST part ----------------------------------------------------
        rows_lfst = [f"lfst_row_{i}" for i in range(self.size_LFST)]
        df_lfst   = pd.DataFrame(self._cm_lfst._hits,
                                 index=rows_lfst,
                                 columns=self._ops)

        report_df = pd.concat([df_ssit, df_lfst])
        if path:
            report_df.to_csv(path)

        return self.coverage_ratio()

    # -------------- convenience: merged frame for analysis -----------------
    def to_frame(self, stack: bool = True) -> pd.DataFrame:
        """Return a single DataFrame combining SSIT + LFST."""
        df_ssit = self._cm_ssit.to_frame(stack=stack)
        df_ssit.insert(0, "table", "ssit")

        df_lfst = self._cm_lfst.to_frame(stack=stack)
        df_lfst.insert(0, "table", "lfst")

        return pd.concat([df_ssit, df_lfst], ignore_index=True)

    # -------------- convenience: total() passthrough -----------------------
    def total(self, table: str | None = None, **kw) -> int:
        """
        Sum counts under optional constraints.

        Examples
        --------
        total(table='lfst', op='invalidate')
        total(op='write_valid')          # across both tables
        """
        if table is None:
            return self._cm_ssit.total(**kw) + self._cm_lfst.total(**kw)
        if table not in ("ssit", "lfst"):
            raise ValueError("table must be 'ssit' or 'lfst'")
        return self._select_cm(table).total(**kw)



# ---------------------------------------------------------------------------
#  Cache
# ---------------------------------------------------------------------------

class cache:
    _ops = ["ReadMiss", "WriteMiss", "ReadHit", "WriteHit", "EvictClean", "EvictDirty"]
    def __init__(self, num_way, num_set):
        self.num_set = num_set
        self.num_way = num_way
        self._cm = CoverageMatrix(
            axes={
                "set": range(self.num_set),
                "way": range(self.num_way),
                "op":    self._ops,
            }
        )
        self.N_EVENTS = self._cm._hits.size
        self.undefined_events = []

    def log_event(self, set, way, op):
        set = int(set)
        way = int(way)
        try:
            self._cm.incr(set=set, way=way, op=op)
        except KeyError:
            print(f"undefined set={set} way={way} op={op}")
            self.undefined_events.append(f"set={set} way={way} op={op}")

    # def coverage_report(self, path):
    #     cov = self._cm.coverage_ratio()
    #     return cov

    def coverage_report(self, path: str | None = None) -> float:
        """
        Returns overall coverage (0.0??C1.0) and optionally writes a CSV with a
        (set-way) x op table of hit counts.
        """
        cov = self._cm.coverage_ratio()

        # _hits shape: (num_set, num_way, num_ops)
        # Flatten (set, way) into one axis to get 2-D for DataFrame
        hits_2d = self._cm._hits.reshape(self.num_set * self.num_way, len(self._ops))

        idx = [f"set-{i}-way-{j}" for i in range(self.num_set) for j in range(self.num_way)]
        cols = list(self._ops)
        df = pd.DataFrame(hits_2d, index=idx, columns=cols)

        if path:
            df.to_csv(path, index=True)

        return cov


    def total(self, **constraints) -> int:
        """Sum counts that meet the given constraints (leave axis absent/None for all)."""
        return int(self._cm.total(**constraints))



"""
O3CPU architecture set up

All modules:
issue_queue
rob
rmt
bpt_local
bpt_bi
store_set
"""

# ALU
NBITS_ADDER = 32
NBITS_MUL = 32
num_IntAlu = 6
num_MulAlu = 6
