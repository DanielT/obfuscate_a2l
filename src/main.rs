use gimli::{EndianSlice, RunTimeEndian};
use memmap2;
use object::build::elf::SectionData;
use std::{collections::HashMap, ffi::OsStr, fs::File};

type SliceType<'a> = EndianSlice<'a, RunTimeEndian>;

mod a2l;
mod dwarf;

fn main() -> Result<(), String> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 5 {
        eprintln!(
            "Usage: {} <input ELF> <output ELF> <input A2L> <output A2L>",
            args[0].to_string_lossy()
        );
        std::process::exit(1);
    }

    run(&args[1], &args[2], &args[3], &args[4])
}

fn run(
    elf_filename_in: &OsStr,
    elf_filename_out: &OsStr,
    a2l_filename_in: &OsStr,
    a2l_filename_out: &OsStr,
) -> Result<(), String> {
    let input_data = load_filedata(elf_filename_in)?;

    let mut elf_builder =
        object::build::elf::Builder::read(&*input_data).map_err(|e| e.to_string())?;

    cleanup_file(&mut elf_builder);

    let stringmapping = obfuscate_debug_info(&mut elf_builder)?;

    let output = std::fs::File::create(elf_filename_out).map_err(|e| e.to_string())?;
    let mut buffer = object::write::StreamingBuffer::new(output);
    elf_builder.write(&mut buffer).map_err(|e| e.to_string())?;

    a2l::obfuscate_a2l(
        a2l_filename_in,
        a2l_filename_out,
        elf_filename_out,
        &stringmapping,
    )?;

    Ok(())
}

/// remove all sections that are not .debug_<xyz> as well as all other items that are unrelated to debug info
fn cleanup_file(elf_builder: &mut object::build::elf::Builder<'_>) {
    for seg in &mut elf_builder.segments {
        seg.delete = true;
    }
    for sec in &mut elf_builder.sections {
        // keep only the sections that start with .debug or .shstrtab (mandatory)
        if !sec.name.starts_with(".debug".as_bytes())
            && !sec.name.starts_with(".shstrtab".as_bytes())
        {
            sec.delete = true;
        }
    }
    for sym in &mut elf_builder.symbols {
        sym.delete = true;
    }
    for dyn_sym in &mut elf_builder.dynamic_symbols {
        dyn_sym.delete = true;
    }
    for gnu_ver in &mut elf_builder.versions {
        gnu_ver.delete = true;
    }
    for gnu_ver_files in &mut elf_builder.version_files {
        gnu_ver_files.delete = true;
    }
    elf_builder.delete_orphans();
    elf_builder.delete_unused_versions();
    elf_builder.set_section_sizes();
}

/// create new DWAR debug info based on the existing info - but obfuscated
fn obfuscate_debug_info(
    elf_builder: &mut object::build::elf::Builder<'_>,
) -> Result<HashMap<String, String>, String> {
    let input_dwarf = load_dwarf_sections(elf_builder).map_err(|e| e.to_string())?;
    let Some((mut output_dwarf, stringmapping)) =
        dwarf::obfuscate_dwarf(input_dwarf).map_err(|e| e.to_string())?
    else {
        eprintln!("Error: no dwarf sections found in input file");
        std::process::exit(1);
    };
    let gimli_endian = match elf_builder.endian {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let mut sections = gimli::write::Sections::new(gimli::write::EndianVec::new(gimli_endian));
    output_dwarf
        .write(&mut sections)
        .map_err(|e| e.to_string())?;

    // add the new debug sections to the elf file
    sections.for_each(|id, data| -> Result<(), String> {
        if !data.slice().is_empty() {
            if let Some(sec) = elf_builder
                .sections
                .iter_mut()
                .find(|s| &*s.name == id.name().as_bytes())
            {
                sec.delete = false;
                sec.data = SectionData::Data(data.clone().into_vec().into());
            } else {
                return Err(format!(
                    "obfuscate is trying to add a section that does not exist in the input file: {} with {} bytes",
                    id.name(), data.slice().len()
                ));
            }
        } else {
            // if the section is empty, remove it from the elf file
            if let Some(sec) = elf_builder
                .sections
                .iter_mut()
                .find(|s| &*s.name == id.name().as_bytes())
            {
                sec.delete = true;
            }
        }

        Ok(())
    })?;

    Ok(stringmapping)
}

/// open a file and mmap its content
fn load_filedata(filename: &OsStr) -> Result<memmap2::Mmap, String> {
    let file = match File::open(filename) {
        Ok(file) => file,
        Err(error) => {
            return Err(format!(
                "Error: could not open file {}: {error}",
                filename.to_string_lossy()
            ));
        }
    };

    match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => Ok(mmap),
        Err(err) => Err(format!(
            "Error: Failed to map file '{}': {err}",
            filename.to_string_lossy()
        )),
    }
}

// load the DWARF debug info from the .debug_<xyz> sections
fn load_dwarf_sections<'data>(
    elf_builder: &'data object::build::elf::Builder<'data>,
) -> Result<gimli::Dwarf<SliceType<'data>>, String> {
    // Dwarf::load takes two closures / functions and uses them to load all the required debug sections
    let loader = |section: gimli::SectionId| get_file_section_reader(elf_builder, section.name());
    gimli::Dwarf::load(loader)
}

// get a section from the elf file.
// returns a slice referencing the section data if it exists, or an empty slice otherwise
fn get_file_section_reader<'data>(
    elf_builder: &'data object::build::elf::Builder<'data>,
    section_name: &str,
) -> Result<SliceType<'data>, String> {
    let gimli_endian = match elf_builder.endian {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };

    for sec in &elf_builder.sections {
        if &*sec.name == section_name.as_bytes() {
            if let SectionData::Data(data) = &sec.data {
                let input: &[u8] = &*data;
                return Ok(EndianSlice::new(input, gimli_endian));
            } else {
                return Err(format!(
                    "Error: section {section_name} is not a data section"
                ));
            }
        }
    }

    Ok(EndianSlice::new(&[], gimli_endian))
}
