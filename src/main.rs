use elf::{
    abi, file::Elf64_Ehdr, relocation::Elf64_Rela, section::Elf64_Shdr, segment::Elf64_Phdr,
};
use region::{alloc, alloc_at, protect, Allocation, Protection};
use std::{
    arch::asm,
    cmp::{max, min},
    env,
    error::Error,
    ffi::CString,
    mem::transmute,
    ptr::write_unaligned,
    slice::{from_raw_parts, from_raw_parts_mut},
};

fn as_custom_slice<T>(bytes: &[u8], len: usize) -> &[T] {
    unsafe { from_raw_parts::<T>(bytes.as_ptr().cast(), len) }
}

fn flags_to_prot(mut p_flags: u32) -> region::Protection {
    [4, 2, 1].iter().fold(Protection::NONE, |mut acc, x| {
        if p_flags >= *x {
            match x {
                4 => acc |= Protection::READ,
                2 => acc |= Protection::WRITE,
                1 => acc |= Protection::EXECUTE,
                _ => acc |= Protection::NONE,
            }
            p_flags -= x;
        }
        acc
    })
}

unsafe fn apply_irelative_relocation(base: *const u8, rela: &Elf64_Rela) {
    let selector: extern "C" fn() -> u64 =
        transmute(base.wrapping_add(rela.r_addend.try_into().unwrap()));

    // write into GOT table entry
    write_unaligned(
        base.wrapping_add(rela.r_offset as usize)
            .cast::<u64>()
            .cast_mut(),
        selector(),
    );
}

unsafe fn apply_relative_relocation(base: *const u8, rela: &Elf64_Rela) {
    write_unaligned(
        base.wrapping_add(rela.r_offset as usize)
            .cast::<u64>()
            .cast_mut(),
        transmute::<_, u64>(base) + rela.r_addend as u64,
    )
}

fn apply_relocations(rela_tbl: &[Elf64_Rela], base: *const u8) {
    rela_tbl.iter().for_each(|rela| {
        let elf64_r_type = |i: u64| (i & 0xffffffff).try_into().unwrap();
        match elf64_r_type(rela.r_info) {
            abi::R_X86_64_IRELATIVE => unsafe { apply_irelative_relocation(base, rela) },
            abi::R_X86_64_RELATIVE => unsafe { apply_relative_relocation(base, rela) },
            _ => (),
        }
    });
}

unsafe fn mprotect_segment(base: *const u8, ph: &Elf64_Phdr) {
    protect(
        base.wrapping_add(ph.p_vaddr as usize),
        ph.p_memsz as usize,
        flags_to_prot(ph.p_flags),
    )
    .unwrap()
}

fn memcpy_segment(bytes: &[u8], ph: &Elf64_Phdr, map_start: *const u8) {
    unsafe {
        bytes
            .as_ptr()
            .wrapping_add(ph.p_offset as usize)
            .copy_to_nonoverlapping(map_start.cast_mut(), ph.p_filesz as usize)
    };
}

fn mmap_segment(base: *const u8, ph: &Elf64_Phdr) -> (*const u8, Allocation) {
    let map_start = base.wrapping_add(ph.p_vaddr as usize);
    let map = alloc_at(map_start, ph.p_memsz as usize, Protection::all()).unwrap();
    (map_start, map)
}

fn init_bss(map_start: *const u8, ph: &Elf64_Phdr) {
    let gap_to_0_out = ph.p_memsz - ph.p_filesz;
    if gap_to_0_out > 0 {
        let slice = unsafe {
            from_raw_parts_mut(
                map_start.wrapping_add(ph.p_offset as usize).cast_mut(),
                gap_to_0_out as usize,
            )
        };
        slice.iter_mut().for_each(|byte| *byte = 0);
    }
}

fn build_stack(
    argc: usize,
    args: &Vec<CString>,
    env: &Vec<CString>,
    auxv: &Vec<(u64, u64)>,
) -> Vec<u64> {
    let mut stack = Vec::new();
    macro_rules! push {
        ($x:expr) => {
            stack.push($x as u64)
        };
    }
    const NULL: u64 = 0;
    push!(argc);
    args.iter().for_each(|arg| push!(arg.as_ptr()));
    push!(NULL);
    env.iter().for_each(|v| push!(v.as_ptr()));
    push!(NULL);
    auxv.iter().for_each(|&(r#type, value)| {
        push!(r#type);
        push!(value);
    });
    push!(NULL);
    push!(NULL);

    if stack.len() % 2 == 1 {
        push!(NULL);
    }
    stack
}

unsafe fn jump(entry_point: *const u8, sp: *const u64) -> ! {
    asm!(
        "mov rsp, {sp}",
        "xor rdx, rdx",
        "jmp {entry_point}",
        entry_point = in(reg) entry_point as u64,
        sp = in(reg) sp as u64,
    );
    loop {}
}

fn get_fixed_auxv(
    base: *const u8,
    ehdr: &Elf64_Ehdr,
    entry_point: *const u8,
    input_path: *const u8,
) -> Vec<(u64, u64)> {
    extern "C" {
        // from libc
        fn getauxval(r#type: u64) -> u64;
    }

    /// Program headers for program
    const AT_PHDR: u64 = 3;
    /// Size of program header entry
    const AT_PHENT: u64 = 4;
    /// Number of program headers
    const AT_PHNUM: u64 = 5;
    /// Entry point of program
    const AT_ENTRY: u64 = 9;
    /// Filename of program
    const AT_EXECFN: u64 = 31;

    let auxv: Vec<_> = (2_u64..=47)
        .into_iter()
        .filter_map(|r#type| unsafe {
            match getauxval(r#type) {
                0 => None,
                value => match r#type {
                    AT_PHDR => Some((r#type, base.wrapping_add(ehdr.e_phoff as usize) as u64)),
                    AT_PHNUM => Some((r#type, ehdr.e_phnum.into())),
                    AT_PHENT => Some((r#type, ehdr.e_phentsize.into())),
                    AT_ENTRY => Some((r#type, entry_point as u64)),
                    AT_EXECFN => Some((r#type, input_path as u64)),
                    _ => Some((r#type, value)),
                },
            }
        })
        .collect();
    auxv
}

fn get_base(load_phdrs: Vec<&Elf64_Phdr>) -> *const u8 {
    let mem_range = load_phdrs
        .iter()
        .fold((std::u64::MAX, std::u64::MIN), |acc, x| {
            (min(acc.0, x.p_vaddr), max(acc.1, x.p_vaddr + x.p_memsz))
        });

    /* For dynamic ELF let the kernel chose the address. */
    /* Check that we can hold the whole image. */
    // temporary value (aka mapping) gets dropped
    let base = alloc((mem_range.1 - mem_range.0) as usize, Protection::READ_WRITE)
        .unwrap()
        .as_ptr::<u8>()
        .wrapping_sub(mem_range.0 as usize);
    base
}
fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: loader [program]...");
    let input_path = std::fs::canonicalize(input_path)?;
    let bytes = std::fs::read(&input_path)?;

    let ehdr = &as_custom_slice::<Elf64_Ehdr>(&bytes, 1)[0];
    let phdrs = as_custom_slice::<Elf64_Phdr>(&bytes[ehdr.e_phoff as usize..], ehdr.e_phnum.into());
    let shdrs = as_custom_slice::<Elf64_Shdr>(&bytes[ehdr.e_shoff as usize..], ehdr.e_shnum.into());

    let load_phdrs_iter = phdrs.iter().filter(|ph| ph.p_type == abi::PT_LOAD);

    let base = get_base(load_phdrs_iter.clone().collect());
    let entry_point = base.wrapping_add(ehdr.e_entry as usize);
    let load_phdrs_iter = load_phdrs_iter.into_iter().filter(|ph| ph.p_memsz > 0);

    // don't let them drop!
    let _maps: Vec<_> = load_phdrs_iter
        .clone()
        .map(|ph| {
            let (map_start, map) = mmap_segment(base, ph);
            init_bss(map_start, ph);
            memcpy_segment(&bytes, ph, map_start);
            map
        })
        .collect();

    if let Some(sh) = shdrs.iter().find(|sh| sh.sh_type == abi::SHT_RELA) {
        let rela_tbl = as_custom_slice::<Elf64_Rela>(
            &bytes[sh.sh_offset as usize..],
            (sh.sh_size / sh.sh_entsize) as usize,
        );
        apply_relocations(rela_tbl, base);
    };

    load_phdrs_iter
        .clone()
        .for_each(|ph| unsafe { mprotect_segment(base, ph) });

    let args: Vec<_> = env::args()
        .skip(1)
        .map(|arg| CString::new(arg).unwrap())
        .collect();
    let argc = args.len();
    let env: Vec<_> = env::vars()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
        .collect();
    let auxv = get_fixed_auxv(base, ehdr, entry_point, args[0].as_ptr().cast());

    let stack_data = build_stack(argc, &args, &env, &auxv);
    let stack_len = stack_data.len();

    const STACK_SIZE: usize = 10000;
    let mut stack: [u64; STACK_SIZE] = [0; STACK_SIZE];
    (0..=(stack_len - 1)).into_iter().rev().for_each(|i| {
        stack[STACK_SIZE - stack_len + i] = stack_data[i];
    });

    unsafe {
        jump(
            entry_point,
            stack.as_ptr().wrapping_add(STACK_SIZE - stack_len),
        )
    };
}
