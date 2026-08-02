use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use ghostscope_process::pinned_bpf_maps::{
    cleanup_current_pinned_maps, ensure_pinned_proc_module_ranges_exist,
    proc_module_range_meta_pin_path, proc_module_ranges_pin_path, replace_ranges_for_pid,
    ProcModuleOffsetsValue, ProcModuleRangeKey, ProcModuleRangeMeta, ProcModuleRangeValue,
};
use scopeguard::guard;
use serial_test::serial;

fn read_range_meta(pid: u32) -> anyhow::Result<ProcModuleRangeMeta> {
    let map_data = MapData::from_pin(proc_module_range_meta_pin_path()?)?;
    let map = Map::from_map_data(map_data)?;
    let meta = AyaHashMap::<MapData, u32, ProcModuleRangeMeta>::try_from(map)?;
    Ok(meta.get(&pid, 0)?)
}

fn count_range_entries(pid: u32, slot: u32) -> anyhow::Result<usize> {
    let map_data = MapData::from_pin(proc_module_ranges_pin_path()?)?;
    let map = Map::from_map_data(map_data)?;
    let ranges = AyaHashMap::<MapData, ProcModuleRangeKey, ProcModuleRangeValue>::try_from(map)?;
    Ok(ranges
        .keys()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|key| key.pid == pid && key.slot == slot)
        .count())
}

#[test]
#[serial]
fn test_failed_module_range_snapshot_keeps_previous_snapshot_active() -> anyhow::Result<()> {
    cleanup_current_pinned_maps()?;
    let _cleanup = guard((), |_| {
        let _ = cleanup_current_pinned_maps();
    });

    // One configured offset entry gives the double-buffered range map a total
    // capacity of two entries. Keep one entry in the active slot so the second
    // insert into the inactive slot deterministically fails with a full map.
    ensure_pinned_proc_module_ranges_exist(1)?;
    let pid = std::process::id();
    let old_snapshot = [(1, ProcModuleOffsetsValue::new(0, 0, 0, 0, 0x1000, 0x1000))];
    assert_eq!(replace_ranges_for_pid(pid, &old_snapshot)?, 1);
    assert_eq!(read_range_meta(pid)?, ProcModuleRangeMeta::new(1, 1));

    let new_snapshot = [
        (2, ProcModuleOffsetsValue::new(0, 0, 0, 0, 0x2000, 0x1000)),
        (3, ProcModuleOffsetsValue::new(0, 0, 0, 0, 0x4000, 0x1000)),
    ];
    let error = replace_ranges_for_pid(pid, &new_snapshot)
        .expect_err("a full inactive slot must reject the entire snapshot");
    assert!(
        error
            .to_string()
            .contains("proc_module_ranges insert failed"),
        "unexpected error: {error:#}"
    );

    assert_eq!(
        read_range_meta(pid)?,
        ProcModuleRangeMeta::new(1, 1),
        "the failed snapshot must not replace the active snapshot"
    );
    assert_eq!(
        count_range_entries(pid, 0)?,
        0,
        "the partially written inactive snapshot must be rolled back"
    );

    Ok(())
}
