use a2lfile::A2lObjectName;
use std::{collections::HashMap, ffi::OsStr};
use symbol::find_symbol;

mod debuginfo;
mod ifdata;
mod symbol;

pub(crate) fn obfuscate_a2l(
    filename_in: &OsStr,
    filename_out: &OsStr,
    filename_elf: &OsStr,
    dwarf_stringmapping: &HashMap<String, String>,
) -> Result<(), String> {
    let (mut a2l, _) = a2lfile::load(
        filename_in,
        Some(ifdata::A2MLVECTOR_TEXT.to_string()),
        false,
    )
    .map_err(|e| e.to_string())?;

    let debuginfo =
        debuginfo::DebugData::load_dwarf(filename_elf, false).map_err(|e| e.to_string())?;

    a2l.project.name = obfuscate_string(&a2l.project.name);
    a2l.project.long_identifier = obfuscate_string(&a2l.project.long_identifier);

    for idx in 0..a2l.project.module.len() {
        a2l.project
            .module
            .rename_item(idx, &obfuscate_string(a2l.project.module[idx].get_name()));
        a2l.project.module[idx].long_identifier =
            obfuscate_string(&a2l.project.module[idx].long_identifier);

        obfuscate_module(
            &mut a2l.project.module[idx],
            &debuginfo,
            dwarf_stringmapping,
        );
    }

    a2l.write(filename_out, None).map_err(|e| e.to_string())?;
    Ok(())
}

fn obfuscate_module(
    module: &mut a2lfile::Module,
    debuginfo: &debuginfo::DebugData,
    dwarf_stringmapping: &HashMap<String, String>,
) {
    // obfuscate all CHARACTERISTICs in the module
    let mut name_map = HashMap::<String, String>::new();
    for idx in 0..module.characteristic.len() {
        let old_name = module.characteristic[idx].get_name().to_string();
        module
            .characteristic
            .rename_item(idx, &obfuscate_string(&old_name));
        module.characteristic[idx].long_identifier =
            obfuscate_string(&module.characteristic[idx].long_identifier);
        let new_name = module.characteristic[idx].get_name().to_string();
        name_map.insert(old_name, new_name);

        if let Some(display_identifier) = &mut module.characteristic[idx].display_identifier {
            display_identifier.display_name = obfuscate_string(&display_identifier.display_name);
        }

        obfuscate_symbol_link(
            &mut module.characteristic[idx].symbol_link,
            debuginfo,
            dwarf_stringmapping,
        );
        obfuscate_ifdata(
            &mut module.characteristic[idx].if_data,
            debuginfo,
            dwarf_stringmapping,
        );

        // erase the address of the characteristic
        module.characteristic[idx].address = 0;
    }
    update_characteristic_xrefs(module, &name_map);

    // obfuscate all MEASUREMENTs in the module
    name_map.clear();
    for idx in 0..module.measurement.len() {
        let old_name = module.measurement[idx].get_name().to_string();
        module
            .measurement
            .rename_item(idx, &obfuscate_string(&old_name));
        module.measurement[idx].long_identifier =
            obfuscate_string(&module.measurement[idx].long_identifier);
        let new_name = module.measurement[idx].get_name().to_string();
        name_map.insert(old_name, new_name);

        if let Some(display_identifier) = &mut module.measurement[idx].display_identifier {
            display_identifier.display_name = obfuscate_string(&display_identifier.display_name);
        }

        obfuscate_symbol_link(
            &mut module.measurement[idx].symbol_link,
            debuginfo,
            dwarf_stringmapping,
        );
        obfuscate_ifdata(
            &mut module.measurement[idx].if_data,
            debuginfo,
            dwarf_stringmapping,
        );

        // erase the address of the measurement
        if let Some(ecu_address) = &mut module.measurement[idx].ecu_address {
            ecu_address.address = 0;
        }
    }
    update_measurement_xrefs(module, &name_map);

    // obfuscate all AXIS_PTSs in the module
    name_map.clear();
    for idx in 0..module.axis_pts.len() {
        let old_name = module.axis_pts[idx].get_name().to_string();
        module
            .axis_pts
            .rename_item(idx, &obfuscate_string(&old_name));
        module.axis_pts[idx].long_identifier =
            obfuscate_string(&module.axis_pts[idx].long_identifier);
        let new_name = module.axis_pts[idx].get_name().to_string();
        name_map.insert(old_name, new_name);

        if let Some(display_identifier) = &mut module.axis_pts[idx].display_identifier {
            display_identifier.display_name = obfuscate_string(&display_identifier.display_name);
        }

        obfuscate_symbol_link(
            &mut module.axis_pts[idx].symbol_link,
            debuginfo,
            dwarf_stringmapping,
        );
        obfuscate_ifdata(
            &mut module.axis_pts[idx].if_data,
            debuginfo,
            dwarf_stringmapping,
        );

        // erase the address of the axis points
        module.axis_pts[idx].address = 0;
    }
    update_axis_pts_xrefs(module, &name_map);

    // obfuscate all RECORD_LAYOUTs in the module
    name_map.clear();
    for idx in 0..module.record_layout.len() {
        let old_name = module.record_layout[idx].get_name().to_string();
        module
            .record_layout
            .rename_item(idx, &obfuscate_string(&old_name));
        let new_name = module.record_layout[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
    }
    update_record_layout_xrefs(module, &name_map);

    // obfuscate all FUNCTIONs in the module
    name_map.clear();
    for idx in 0..module.function.len() {
        let old_name = module.function[idx].get_name().to_string();
        module
            .function
            .rename_item(idx, &obfuscate_string(&old_name));
        module.function[idx].long_identifier =
            obfuscate_string(&module.function[idx].long_identifier);
        let new_name = module.function[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
    }
    update_function_xrefs(module, &name_map);

    // obfuscate all GROUPs in the module
    name_map.clear();
    for idx in 0..module.group.len() {
        let old_name = module.group[idx].get_name().to_string();
        module.group.rename_item(idx, &obfuscate_string(&old_name));
        module.group[idx].long_identifier = obfuscate_string(&module.group[idx].long_identifier);
        let new_name = module.group[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
    }
    update_group_xrefs(module, &name_map);

    // obfuscate all COMPU_METHODs in the module
    name_map.clear();
    for idx in 0..module.compu_method.len() {
        let old_name = module.compu_method[idx].get_name().to_string();
        module
            .compu_method
            .rename_item(idx, &obfuscate_string(&old_name));
        let new_name = module.compu_method[idx].get_name().to_string();
        name_map.insert(old_name, new_name);

        module.compu_method[idx].unit = obfuscate_string_with_syms(&module.compu_method[idx].unit);
    }
    update_compu_method_xrefs(module, &name_map);

    // obfuscate all COMPU_TABs, COMPU_VTABs and COMPU_VTAB_RANGEs in the module
    name_map.clear();
    for idx in 0..module.compu_tab.len() {
        let old_name = module.compu_tab[idx].get_name().to_string();
        module
            .compu_tab
            .rename_item(idx, &obfuscate_string(&old_name));
        let new_name = module.compu_tab[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
        module.compu_tab[idx].long_identifier =
            obfuscate_string(&module.compu_tab[idx].long_identifier);
    }
    for idx in 0..module.compu_vtab.len() {
        let old_name = module.compu_vtab[idx].get_name().to_string();
        module
            .compu_vtab
            .rename_item(idx, &obfuscate_string(&old_name));
        let new_name = module.compu_vtab[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
        module.compu_vtab[idx].long_identifier =
            obfuscate_string(&module.compu_vtab[idx].long_identifier);

        for value_pair in module.compu_vtab[idx].value_pairs.iter_mut() {
            value_pair.out_val = obfuscate_string(&value_pair.out_val);
        }
    }
    for idx in 0..module.compu_vtab_range.len() {
        let old_name = module.compu_vtab_range[idx].get_name().to_string();
        module
            .compu_vtab_range
            .rename_item(idx, &obfuscate_string(&old_name));
        let new_name = module.compu_vtab_range[idx].get_name().to_string();
        name_map.insert(old_name, new_name);
        module.compu_vtab_range[idx].long_identifier =
            obfuscate_string(&module.compu_vtab_range[idx].long_identifier);

        for value_triple in module.compu_vtab_range[idx].value_triples.iter_mut() {
            value_triple.out_val = obfuscate_string(&value_triple.out_val);
        }
    }
    update_compu_tabs_xrefs(module, &name_map);
}

fn obfuscate_symbol_link(
    opt_symbol_link: &mut Option<a2lfile::SymbolLink>,
    debuginfo: &debuginfo::DebugData,
    dwarf_stringmapping: &HashMap<String, String>,
) {
    if let Some(symbol_link) = opt_symbol_link {
        if let Ok(sym_info) = find_symbol(&symbol_link.symbol_name, debuginfo, dwarf_stringmapping)
        {
            symbol_link.symbol_name = sym_info.name;
        }
    } else {
        *opt_symbol_link = None;
    }
}

fn obfuscate_ifdata(
    ifdata_vec: &mut Vec<a2lfile::IfData>,
    debuginfo: &debuginfo::DebugData,
    dwarf_stringmapping: &HashMap<String, String>,
) {
    for ifdata in ifdata_vec {
        if let Some(mut decoded_ifdata) = ifdata::A2mlVector::load_from_ifdata(ifdata) {
            if let Some(canape_ext) = &mut decoded_ifdata.canape_ext {
                if let Some(link_map) = &mut canape_ext.link_map {
                    if let Ok(sym_info) =
                        find_symbol(&link_map.symbol_name, debuginfo, dwarf_stringmapping)
                    {
                        link_map.symbol_name = sym_info.name;
                    } else {
                        // if the symbol is not found, we obfuscate it
                        link_map.symbol_name = obfuscate_string(&link_map.symbol_name);
                    }
                    decoded_ifdata.store_to_ifdata(ifdata);
                }
            }
        }
    }
}

fn update_characteristic_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for characteristic in &mut module.characteristic {
        if let Some(dependent_characteristic) = &mut characteristic.dependent_characteristic {
            let old_dependen_charistics =
                std::mem::take(&mut dependent_characteristic.characteristic_list);
            for dep_char in old_dependen_charistics {
                if let Some(new_name) = name_map.get(&dep_char) {
                    // update the name of the dependent characteristic
                    dependent_characteristic
                        .characteristic_list
                        .push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    dependent_characteristic
                        .characteristic_list
                        .push(obfuscate_string(&dep_char));
                }
            }
        }

        if let Some(map_list) = &mut characteristic.map_list {
            let old_map_list = std::mem::take(&mut map_list.name_list);
            for map in old_map_list {
                if let Some(new_name) = name_map.get(&map) {
                    // update the name of the map
                    map_list.name_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    map_list.name_list.push(obfuscate_string(&map));
                }
            }
        }

        if let Some(virtual_characteristic) = &mut characteristic.virtual_characteristic {
            let old_virtual_characteristic =
                std::mem::take(&mut virtual_characteristic.characteristic_list);
            for virt_char in old_virtual_characteristic {
                if let Some(new_name) = name_map.get(&virt_char) {
                    // update the name of the virtual characteristic
                    virtual_characteristic
                        .characteristic_list
                        .push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    virtual_characteristic
                        .characteristic_list
                        .push(obfuscate_string(&virt_char));
                }
            }
        }
    }

    for function in &mut module.function {
        if let Some(def_characteristic) = &mut function.def_characteristic {
            let old_def_characteristic = std::mem::take(&mut def_characteristic.identifier_list);
            for def_char in old_def_characteristic {
                if let Some(new_name) = name_map.get(&def_char) {
                    // update the name of the def characteristic
                    def_characteristic.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    def_characteristic
                        .identifier_list
                        .push(obfuscate_string(&def_char));
                }
            }
        }

        if let Some(ref_characteristic) = &mut function.ref_characteristic {
            let old_ref_characteristic = std::mem::take(&mut ref_characteristic.identifier_list);
            for ref_char in old_ref_characteristic {
                if let Some(new_name) = name_map.get(&ref_char) {
                    // update the name of the ref characteristic
                    ref_characteristic.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    ref_characteristic
                        .identifier_list
                        .push(obfuscate_string(&ref_char));
                }
            }
        }
    }

    for group in &mut module.group {
        if let Some(ref_characteristic) = &mut group.ref_characteristic {
            let old_ref_characteristic = std::mem::take(&mut ref_characteristic.identifier_list);
            for def_char in old_ref_characteristic {
                if let Some(new_name) = name_map.get(&def_char) {
                    // update the name of the def characteristic
                    ref_characteristic.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    ref_characteristic
                        .identifier_list
                        .push(obfuscate_string(&def_char));
                }
            }
        }
    }

    for transformer in &mut module.transformer {
        if let Some(transformer_in_objects) = &mut transformer.transformer_in_objects {
            let old_transformer_in_objects =
                std::mem::take(&mut transformer_in_objects.identifier_list);
            for transformer_in_object in old_transformer_in_objects {
                if let Some(new_name) = name_map.get(&transformer_in_object) {
                    // update the name of the transformer in object
                    transformer_in_objects
                        .identifier_list
                        .push(new_name.clone());
                } else {
                    // the transformer does not refer to a characteristic but to some other object
                    // it will be updated later
                }
            }
        }

        if let Some(transformer_out_objects) = &mut transformer.transformer_out_objects {
            let old_transformer_out_objects =
                std::mem::take(&mut transformer_out_objects.identifier_list);
            for transformer_out_object in old_transformer_out_objects {
                if let Some(new_name) = name_map.get(&transformer_out_object) {
                    // update the name of the transformer out object
                    transformer_out_objects
                        .identifier_list
                        .push(new_name.clone());
                } else {
                    // the transformer does not refer to a characteristic but to some other object
                    // it will be updated later
                }
            }
        }
    }
}

fn update_measurement_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for characteristic in &mut module.characteristic {
        for axis_descr in &mut characteristic.axis_descr {
            if let Some(new_name) = name_map.get(&axis_descr.input_quantity) {
                // update the name of the axis descriptor
                axis_descr.input_quantity = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                axis_descr.input_quantity = obfuscate_string(&axis_descr.input_quantity);
            }
        }

        if let Some(comparison_quantity) = &mut characteristic.comparison_quantity {
            if let Some(new_name) = name_map.get(&comparison_quantity.name) {
                // update the name of the comparison quantity
                comparison_quantity.name = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                comparison_quantity.name = obfuscate_string(&comparison_quantity.name);
            }
        }
    }

    for typedef_axis in &mut module.typedef_axis {
        if let Some(new_name) = name_map.get(&typedef_axis.input_quantity) {
            // update the name of the typedef axis
            typedef_axis.input_quantity = new_name.clone();
        } else {
            // invalid ref without an old name, so we obfuscate it
            typedef_axis.input_quantity = obfuscate_string(&typedef_axis.input_quantity);
        }
    }

    for axis_pts in &mut module.axis_pts {
        if let Some(new_name) = name_map.get(&axis_pts.input_quantity) {
            // update the name of the axis points
            axis_pts.input_quantity = new_name.clone();
        } else {
            // invalid ref without an old name, so we obfuscate it
            axis_pts.input_quantity = obfuscate_string(&axis_pts.input_quantity);
        }
    }

    for function in &mut module.function {
        if let Some(in_measurement) = &mut function.in_measurement {
            let old_in_measurement = std::mem::take(&mut in_measurement.identifier_list);
            for name in old_in_measurement {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the in measurement
                    in_measurement.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    in_measurement.identifier_list.push(obfuscate_string(&name));
                }
            }
        }
        if let Some(out_measurement) = &mut function.out_measurement {
            let old_out_measurement = std::mem::take(&mut out_measurement.identifier_list);
            for name in old_out_measurement {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the out measurement
                    out_measurement.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    out_measurement
                        .identifier_list
                        .push(obfuscate_string(&name));
                }
            }
        }
        if let Some(loc_measurement) = &mut function.loc_measurement {
            let old_loc_measurement = std::mem::take(&mut loc_measurement.identifier_list);
            for name in old_loc_measurement {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the loc measurement
                    loc_measurement.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    loc_measurement
                        .identifier_list
                        .push(obfuscate_string(&name));
                }
            }
        }
    }

    for group in &mut module.group {
        if let Some(ref_measurement) = &mut group.ref_measurement {
            let old_ref_measurement = std::mem::take(&mut ref_measurement.identifier_list);
            for name in old_ref_measurement {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the ref measurement
                    ref_measurement.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    ref_measurement
                        .identifier_list
                        .push(obfuscate_string(&name));
                }
            }
        }
    }
}

fn update_axis_pts_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for characteristic in &mut module.characteristic {
        for axis_descr in &mut characteristic.axis_descr {
            if let Some(axis_pts_ref) = &mut axis_descr.axis_pts_ref {
                if let Some(new_name) = name_map.get(&axis_pts_ref.axis_points) {
                    // update the name of the axis descriptor
                    axis_pts_ref.axis_points = new_name.clone();
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    axis_pts_ref.axis_points = obfuscate_string(&axis_pts_ref.axis_points);
                }
            }
        }
    }
}

fn update_record_layout_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for axis_pts in &mut module.axis_pts {
        if let Some(new_name) = name_map.get(&axis_pts.deposit_record) {
            // update the name of the axis points
            axis_pts.deposit_record = new_name.clone();
        } else {
            // invalid ref without an old name, so we obfuscate it
            axis_pts.deposit_record = obfuscate_string(&axis_pts.deposit_record);
        }
    }

    for characteristic in &mut module.characteristic {
        if let Some(new_name) = name_map.get(&characteristic.deposit) {
            // update the name of the deposit
            characteristic.deposit = new_name.clone();
        } else {
            // invalid ref without an old name, so we obfuscate it
            characteristic.deposit = obfuscate_string(&characteristic.deposit);
        }
    }
}

fn update_function_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for function in &mut module.function {
        if let Some(sub_function) = &mut function.sub_function {
            let old_sub_function = std::mem::take(&mut sub_function.identifier_list);
            for name in old_sub_function {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the sub function
                    sub_function.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    sub_function.identifier_list.push(obfuscate_string(&name));
                }
            }
        }
    }

    for axis_pts in &mut module.axis_pts {
        if let Some(function_list) = &mut axis_pts.function_list {
            let old_function_list = std::mem::take(&mut function_list.name_list);
            for name in old_function_list {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the function list
                    function_list.name_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    function_list.name_list.push(obfuscate_string(&name));
                }
            }
        }
    }

    for characteristic in &mut module.characteristic {
        if let Some(function_list) = &mut characteristic.function_list {
            let old_function_list = std::mem::take(&mut function_list.name_list);
            for name in old_function_list {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the function list
                    function_list.name_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    function_list.name_list.push(obfuscate_string(&name));
                }
            }
        }
    }

    for measurement in &mut module.measurement {
        if let Some(function_list) = &mut measurement.function_list {
            let old_function_list = std::mem::take(&mut function_list.name_list);
            for name in old_function_list {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the function list
                    function_list.name_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    function_list.name_list.push(obfuscate_string(&name));
                }
            }
        }
    }

    for group in &mut module.group {
        if let Some(function_list) = &mut group.function_list {
            let old_function_list = std::mem::take(&mut function_list.name_list);
            for name in old_function_list {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the function list
                    function_list.name_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    function_list.name_list.push(obfuscate_string(&name));
                }
            }
        }
    }
}

fn update_group_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for group in &mut module.group {
        if let Some(sub_group) = &mut group.sub_group {
            let old_sub_group = std::mem::take(&mut sub_group.identifier_list);
            for name in old_sub_group {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the sub group
                    sub_group.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    sub_group.identifier_list.push(obfuscate_string(&name));
                }
            }
        }
    }

    for user_rights in &mut module.user_rights {
        for ref_group in &mut user_rights.ref_group {
            let old_ref_group = std::mem::take(&mut ref_group.identifier_list);
            for name in old_ref_group {
                if let Some(new_name) = name_map.get(&name) {
                    // update the name of the ref group
                    ref_group.identifier_list.push(new_name.clone());
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    ref_group.identifier_list.push(obfuscate_string(&name));
                }
            }
        }
    }
}

fn update_compu_method_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for axis_pts in &mut module.axis_pts {
        if axis_pts.conversion != "NO_COMPU_METHOD" {
            if let Some(new_name) = name_map.get(&axis_pts.conversion) {
                // update the name of the axis points
                axis_pts.conversion = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                axis_pts.conversion = obfuscate_string(&axis_pts.conversion);
            }
        }
    }

    for characteristic in &mut module.characteristic {
        for axis_descr in &mut characteristic.axis_descr {
            if axis_descr.conversion != "NO_COMPU_METHOD" {
                if let Some(new_name) = name_map.get(&axis_descr.conversion) {
                    // update the name of the axis descriptor
                    axis_descr.conversion = new_name.clone();
                } else {
                    // invalid ref without an old name, so we obfuscate it
                    axis_descr.conversion = obfuscate_string(&axis_descr.conversion);
                }
            }
        }

        if characteristic.conversion != "NO_COMPU_METHOD" {
            if let Some(new_name) = name_map.get(&characteristic.conversion) {
                // update the name of the characteristic conversion
                characteristic.conversion = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                characteristic.conversion = obfuscate_string(&characteristic.conversion);
            }
        }
    }

    for measurement in &mut module.measurement {
        if measurement.conversion != "NO_COMPU_METHOD" {
            if let Some(new_name) = name_map.get(&measurement.conversion) {
                // update the name of the measurement conversion
                measurement.conversion = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                measurement.conversion = obfuscate_string(&measurement.conversion);
            }
        }
    }
}

fn update_compu_tabs_xrefs(module: &mut a2lfile::Module, name_map: &HashMap<String, String>) {
    for compu_method in &mut module.compu_method {
        if let Some(compu_tab_ref) = &mut compu_method.compu_tab_ref {
            if let Some(new_name) = name_map.get(&compu_tab_ref.conversion_table) {
                // update the name of the compu tab ref
                compu_tab_ref.conversion_table = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                compu_tab_ref.conversion_table = obfuscate_string(&compu_tab_ref.conversion_table);
            }
        }
        if let Some(status_string_ref) = &mut compu_method.status_string_ref {
            if let Some(new_name) = name_map.get(&status_string_ref.conversion_table) {
                // update the name of the status string ref
                status_string_ref.conversion_table = new_name.clone();
            } else {
                // invalid ref without an old name, so we obfuscate it
                status_string_ref.conversion_table =
                    obfuscate_string(&status_string_ref.conversion_table);
            }
        }
    }
}

// weak obfuscation function that replaces all alphabetic characters with random ones
// this is not a real obfuscation, but it is enough to make the string unreadable
// non-alphabetic characters are not changed, so Abc.foo[33] will become Xyz.bar[33]
fn obfuscate_string(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphabetic() {
            let randchar = if c.is_ascii_uppercase() {
                rand::random_range(0..26) + b'A'
            } else {
                rand::random::<u8>() % 26 + b'a'
            } as char;
            output.push(randchar);
        } else {
            output.push(c);
        }
    }

    output
}

// weak obfuscation function that replaces all alphabetic characters with random ones
// this is not a real obfuscation, but it is enough to make the string unreadable
// non-alphabetic characters are not changed, so Abc.foo[33] will become Xyz.bar[33]
fn obfuscate_string_with_syms(input: &str) -> String {
    static CHARLIST: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-/?!";
    let mut output = String::with_capacity(input.len());
    for _ in 0..input.len() {
        let randchar = CHARLIST[rand::random_range(0..CHARLIST.len())] as char;
        output.push(randchar);
    }

    output
}
