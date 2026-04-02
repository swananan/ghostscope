#[inline]
pub(crate) fn range_contains_pc(lo: u64, hi: u64, pc: u64) -> bool {
    if lo == hi {
        pc == lo
    } else {
        pc >= lo && pc < hi
    }
}

#[inline]
pub(crate) fn ranges_contain_pc(ranges: &[(u64, u64)], pc: u64) -> bool {
    ranges.iter().any(|&(lo, hi)| range_contains_pc(lo, hi, pc))
}
