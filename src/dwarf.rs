use gimli::{
    Dwarf, EndianSlice, RunTimeEndian,
    write::{UnitEntryId, UnitId},
};
use std::{collections::HashMap, vec};

type SliceType<'a> = EndianSlice<'a, RunTimeEndian>;

pub(crate) fn obfuscate_dwarf(
    input_dwarf: Dwarf<EndianSlice<RunTimeEndian>>,
) -> Result<Option<(gimli::write::Dwarf, HashMap<String, String>)>, String> {
    let mut output_dwarf = gimli::write::Dwarf::new();

    let mut debuginfo_offsets = HashMap::<usize, (UnitId, UnitEntryId)>::new();
    let mut per_unit_offsets = vec![];

    // mapping table from original strings to obfuscated strings
    // this ensures that the same string is obfuscated to the same value
    let mut obfuscated_strings = HashMap::<String, String>::new();

    let mut output_unit_ids = vec![];

    // handle the dwarf info in two passes:
    // - first pass: create all units amd all debug info entries in the units, while building
    //   a mapping table for all input unit offsets and debuginfo offsets to the newly created unit entry ids
    // - second pass: add all attributes to the entries in the output unit, using the mapping table from the first pass
    //   While handling the attributes, we also obfuscate the names of the variables and functions

    // pass 1
    let mut unit_iter = input_dwarf.debug_info.units();
    while let Ok(Some(unit)) = unit_iter.next() {
        let abbreviations = unit.abbreviations(&input_dwarf.debug_abbrev).unwrap();
        // The root of the tree inside of a unit is always a DW_TAG_compile_unit or DW_TAG_partial_unit.
        let mut entries_cursor = unit.entries(&abbreviations);
        if let Ok(Some((_, entry))) = entries_cursor.next_dfs() {
            if entry.tag() == gimli::constants::DW_TAG_compile_unit
                || entry.tag() == gimli::constants::DW_TAG_partial_unit
            {
                let output_unit =
                    gimli::write::Unit::new(unit.encoding(), gimli::write::LineProgram::none());
                let unit_id = output_dwarf.units.add(output_unit);
                let mut output_unit = output_dwarf.units.get_mut(unit_id);

                let unit_offsets = create_unit_structure(
                    unit_id,
                    &unit,
                    &abbreviations,
                    &mut output_unit,
                    &mut debuginfo_offsets,
                );

                output_unit_ids.push(unit_id);
                per_unit_offsets.push(unit_offsets);
            } else {
                // error
                panic!("impossible: first entry is not a compile unit or partial unit");
            }
        }
    }

    // pass 2
    let mut idx: usize = 0;
    let mut unit_iter = input_dwarf.debug_info.units();
    while let Ok(Some(unit)) = unit_iter.next() {
        let abbreviations = unit.abbreviations(&input_dwarf.debug_abbrev).unwrap();
        // The root of the tree inside of a unit is always a DW_TAG_compile_unit or DW_TAG_partial_unit.
        let mut entries_cursor = unit.entries(&abbreviations);
        if let Ok(Some((_, entry))) = entries_cursor.next_dfs() {
            if entry.tag() == gimli::constants::DW_TAG_compile_unit
                || entry.tag() == gimli::constants::DW_TAG_partial_unit
            {
                idx += 1; // can't use .enumerate() with this custom iterator
                let output_unit = output_dwarf.units.get_mut(output_unit_ids[idx - 1]);
                let unit_offsets = &per_unit_offsets[idx - 1];
                obfuscate_unit(
                    unit,
                    &abbreviations,
                    output_unit,
                    unit_offsets,
                    &debuginfo_offsets,
                    &mut obfuscated_strings,
                    &input_dwarf,
                );
            } else {
                // error
                panic!("impossible: first entry is not a compile unit or partial unit");
            }
        }
    }

    Ok(Some((output_dwarf, obfuscated_strings)))
}

fn create_unit_structure(
    unit_id: UnitId,
    in_unit: &gimli::UnitHeader<EndianSlice<RunTimeEndian>>,
    in_abbrevs: &gimli::Abbreviations,
    output_unit: &mut gimli::write::Unit,
    debuginfo_offsets: &mut HashMap<usize, (UnitId, UnitEntryId)>,
) -> HashMap<usize, UnitEntryId> {
    let mut parent_ids = vec![output_unit.root()];
    let mut depth = 0;
    let mut unit_offsets = HashMap::<usize, UnitEntryId>::new();

    let mut entries_cursor = in_unit.entries(in_abbrevs);
    while let Ok(Some((depth_delta, entry))) = entries_cursor.next_dfs() {
        depth = (depth as isize + depth_delta) as usize;
        parent_ids.truncate(depth + 1);

        // create a new entry in the output unit
        let id = output_unit.add(parent_ids[depth], entry.tag());
        // make the entry id available in the parent_ids list so that sub-entries can be added to it
        parent_ids.push(id);

        // unit_offset in the input corresponds to the entry id in the output unit
        unit_offsets.insert(entry.offset().0, id);
        debuginfo_offsets.insert(
            entry.offset().to_debug_info_offset(in_unit).unwrap().0,
            (unit_id, id),
        );
    }

    unit_offsets
}

fn obfuscate_unit(
    in_unit: gimli::UnitHeader<EndianSlice<RunTimeEndian>>,
    in_abbrevs: &gimli::Abbreviations,
    output_unit: &mut gimli::write::Unit,
    unit_offsets: &HashMap<usize, UnitEntryId>,
    debuginfo_offsets: &HashMap<usize, (UnitId, UnitEntryId)>,
    obfuscated_strings: &mut HashMap<String, String>,
    input_dwarf: &Dwarf<EndianSlice<RunTimeEndian>>,
) {
    let mut entries_cursor = in_unit.entries(in_abbrevs);
    while let Ok(Some((_, entry))) = entries_cursor.next_dfs() {
        let id = unit_offsets.get(&entry.offset().0).unwrap();
        // get the entry in the output unit
        let output_entry = output_unit.get_mut(*id);

        // process attributes
        let mut attrs_iter = entry.attrs();
        while let Ok(Some(attr)) = attrs_iter.next() {
            if let Some(output_value) = obfuscate_attribute_value(
                &in_unit,
                attr.name(),
                attr.value(),
                unit_offsets,
                debuginfo_offsets,
                obfuscated_strings,
                input_dwarf,
            ) {
                output_entry.set(attr.name(), output_value);
            }
        }
    }
}

fn obfuscate_attribute_value(
    input_unit: &gimli::UnitHeader<EndianSlice<RunTimeEndian>>,
    attrtype: gimli::DwAt,
    value: gimli::AttributeValue<SliceType>,
    unit_offsets: &HashMap<usize, UnitEntryId>,
    debuginfo_offsets: &HashMap<usize, (UnitId, UnitEntryId)>,
    obfuscated_strings: &mut HashMap<String, String>,
    input_dwarf: &Dwarf<EndianSlice<RunTimeEndian>>,
) -> Option<gimli::write::AttributeValue> {
    match value {
        gimli::AttributeValue::Addr(val) => Some(gimli::write::AttributeValue::Address(
            gimli::write::Address::Constant(val),
        )),
        gimli::AttributeValue::Block(val) => {
            Some(gimli::write::AttributeValue::Block(val.to_vec()))
        }
        gimli::AttributeValue::Data1(val) => Some(gimli::write::AttributeValue::Data1(val)),
        gimli::AttributeValue::Data2(val) => Some(gimli::write::AttributeValue::Data2(val)),
        gimli::AttributeValue::Data4(val) => Some(gimli::write::AttributeValue::Data4(val)),
        gimli::AttributeValue::Data8(val) => Some(gimli::write::AttributeValue::Data8(val)),
        gimli::AttributeValue::Sdata(val) => Some(gimli::write::AttributeValue::Sdata(val)),
        gimli::AttributeValue::Udata(val) => Some(gimli::write::AttributeValue::Udata(val)),
        gimli::AttributeValue::Exprloc(expression) => {
            let mut evaluation = expression.evaluation(input_unit.encoding());
            evaluation.set_object_address(0);
            evaluation.set_initial_value(0);
            evaluation.set_max_iterations(100);
            let mut eval_result = evaluation.evaluate().unwrap();
            while eval_result != gimli::EvaluationResult::Complete {
                match eval_result {
                    gimli::EvaluationResult::RequiresRelocatedAddress(address) => {
                        // assume that there is no relocation
                        // this would be a bad bet on PC, but on embedded controllers where A2l files are used this is the standard
                        eval_result = evaluation.resume_with_relocated_address(address).unwrap();
                    }
                    _ => return None,
                }
            }
            let result = evaluation.result();
            if let gimli::Piece {
                location: gimli::Location::Address { address },
                ..
            } = result[0]
            {
                let mut obfuscated_address = rand::random::<u64>() & 0xffff_ff00;
                // we're not worried about the content of the lower 8 bits of the address;
                // keeping them preserves alignment, and makes the resulting address more realistic
                obfuscated_address |= address & 0x0000_00ff;
                let mut output_expr = gimli::write::Expression::new();
                output_expr.op_addr(gimli::write::Address::Constant(obfuscated_address));
                Some(gimli::write::AttributeValue::Exprloc(output_expr))
            } else {
                None
            }
        }
        gimli::AttributeValue::Flag(flg) => Some(gimli::write::AttributeValue::Flag(flg)),
        gimli::AttributeValue::SecOffset(_) => None,
        gimli::AttributeValue::DebugAddrBase(debug_addr_base) => {
            println!("DebugAddrBase: {debug_addr_base:#?}");
            None
        }
        gimli::AttributeValue::DebugAddrIndex(_) => None,
        gimli::AttributeValue::UnitRef(unit_offset) => {
            // this is a reference to a unit, we need to find the corresponding entry id in the output unit
            if let Some(entry_id) = unit_offsets.get(&unit_offset.0) {
                Some(gimli::write::AttributeValue::UnitRef(*entry_id))
            } else {
                println!("UnitRef: {:x} not found in unit_offsets", unit_offset.0);
                None
            }
        }
        gimli::AttributeValue::DebugInfoRef(debug_info_offset) => {
            if let Some((unit_id, entry_id)) = debuginfo_offsets.get(&debug_info_offset.0) {
                let reference = gimli::write::Reference::Entry(*unit_id, *entry_id);
                Some(gimli::write::AttributeValue::DebugInfoRef(reference))
            } else {
                println!(
                    "DebugInfoRef: {:x} not found in debuginfo_offsets",
                    debug_info_offset.0
                );
                None
            }
        }
        gimli::AttributeValue::DebugInfoRefSup(_debug_info_offset) => todo!(),
        gimli::AttributeValue::DebugLineRef(_) => None,
        gimli::AttributeValue::LocationListsRef(_) => None,
        gimli::AttributeValue::DebugLocListsBase(_debug_loc_lists_base) => todo!(),
        gimli::AttributeValue::DebugLocListsIndex(_debug_loc_lists_index) => todo!(),
        gimli::AttributeValue::DebugMacinfoRef(_debug_macinfo_offset) => {
            // gimli does not support this (yet?)
            None
        }
        gimli::AttributeValue::DebugMacroRef(_) => None,
        gimli::AttributeValue::RangeListsRef(_) => None,
        gimli::AttributeValue::DebugRngListsBase(_) => None,
        gimli::AttributeValue::DebugRngListsIndex(_) => None,
        gimli::AttributeValue::DebugTypesRef(_debug_type_signature) => todo!(),
        gimli::AttributeValue::DebugStrRef(debug_str_offset) => {
            let strval = input_dwarf.debug_str.get_str(debug_str_offset).ok()?;
            let utf8string = strval.to_string().ok()?;
            if let Some(obfuscated) = obfuscated_strings.get(utf8string) {
                // if we already have an obfuscated string, use it
                Some(gimli::write::AttributeValue::String(
                    obfuscated.as_bytes().to_vec(),
                ))
            } else {
                // otherwise, obfuscate the string and store it in the map
                let obfuscated_name = obfuscate_name(utf8string);
                obfuscated_strings.insert(utf8string.to_string(), obfuscated_name.clone());
                Some(gimli::write::AttributeValue::String(
                    obfuscated_name.as_bytes().to_vec(),
                ))
            }
        }
        gimli::AttributeValue::DebugStrRefSup(_debug_str_offset) => todo!(),
        gimli::AttributeValue::DebugStrOffsetsBase(_debug_str_offsets_base) => todo!(),
        gimli::AttributeValue::DebugStrOffsetsIndex(_debug_str_offsets_index) => todo!(),
        gimli::AttributeValue::DebugLineStrRef(_) => None,
        gimli::AttributeValue::Encoding(dw_ate) => {
            Some(gimli::write::AttributeValue::Encoding(dw_ate))
        }
        gimli::AttributeValue::DecimalSign(dw_ds) => {
            Some(gimli::write::AttributeValue::DecimalSign(dw_ds))
        }
        gimli::AttributeValue::Endianity(dw_end) => {
            Some(gimli::write::AttributeValue::Endianity(dw_end))
        }
        gimli::AttributeValue::Accessibility(dw_access) => {
            Some(gimli::write::AttributeValue::Accessibility(dw_access))
        }
        gimli::AttributeValue::Visibility(dw_vis) => {
            Some(gimli::write::AttributeValue::Visibility(dw_vis))
        }
        gimli::AttributeValue::Virtuality(dw_virtuality) => {
            Some(gimli::write::AttributeValue::Virtuality(dw_virtuality))
        }
        gimli::AttributeValue::Language(dw_lang) => {
            Some(gimli::write::AttributeValue::Language(dw_lang))
        }
        gimli::AttributeValue::AddressClass(dw_addr) => {
            Some(gimli::write::AttributeValue::AddressClass(dw_addr))
        }
        gimli::AttributeValue::IdentifierCase(dw_id) => {
            Some(gimli::write::AttributeValue::IdentifierCase(dw_id))
        }
        gimli::AttributeValue::CallingConvention(dw_cc) => {
            Some(gimli::write::AttributeValue::CallingConvention(dw_cc))
        }
        gimli::AttributeValue::Inline(dw_inl) => Some(gimli::write::AttributeValue::Inline(dw_inl)),
        gimli::AttributeValue::Ordering(dw_ord) => {
            Some(gimli::write::AttributeValue::Ordering(dw_ord))
        }
        gimli::AttributeValue::FileIndex(_) => None,
        gimli::AttributeValue::DwoId(_) => None,
        gimli::AttributeValue::String(strval) => {
            if let Ok(val) = strval.to_string() {
                if attrtype == gimli::constants::DW_AT_name {
                    // this is a name attribute, we can obfuscate it
                    if let Some(obfuscated) = obfuscated_strings.get(val) {
                        // if we already have an obfuscated string, use it
                        Some(gimli::write::AttributeValue::String(
                            obfuscated.as_bytes().to_vec(),
                        ))
                    } else {
                        // otherwise, obfuscate the string and store it in the map
                        let obfuscated_name = obfuscate_name(val);
                        obfuscated_strings.insert(val.to_string(), obfuscated_name.clone());
                        Some(gimli::write::AttributeValue::String(
                            obfuscated_name.as_bytes().to_vec(),
                        ))
                    }
                } else if attrtype == gimli::constants::DW_AT_comp_dir
                    || attrtype == gimli::constants::DW_AT_producer
                {
                    // discard the compilation directory and producer attributes
                    None
                } else {
                    // this is not a name attribute, we can just return the string as is
                    println!("non-obfuscated string: {val} for attrtype {attrtype:?}");
                    Some(gimli::write::AttributeValue::String(
                        val.as_bytes().to_vec(),
                    ))
                }
            } else {
                None
            }
        }
    }
}

// obfuscate a name by replacing it with a random string of the same length
fn obfuscate_name(name: &str) -> String {
    static CHARLIST: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    let mut obfuscated_name = String::with_capacity(name.len());
    obfuscated_name.push((b'a' + rand::random_range(0..26)) as char);
    for _ in 1..name.len() {
        obfuscated_name.push(CHARLIST[rand::random_range(0..CHARLIST.len())] as char);
    }
    obfuscated_name
}
