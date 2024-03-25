use libc::{Elf64_Ehdr, Elf64_Phdr};
use region::{alloc, alloc_at, protect, Allocation, Protection};
use std::{
    arch::asm,
    cmp::{max, min},
    env,
    error::Error,
    ffi::CString,
    mem::transmute,
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::OnceLock,
};

static BASE: OnceLock<u64> = OnceLock::new();
static BYTES: OnceLock<Vec<u8>> = OnceLock::new();

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

unsafe fn mprotect_segment(base: *const u8, ph: &Elf64_Phdr, prots: Protection) {
    protect(
        base.wrapping_add(ph.p_vaddr as usize),
        ph.p_memsz as usize,
        prots,
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
    let map = alloc_at(map_start, ph.p_memsz as usize, Protection::READ_WRITE).unwrap();
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

fn build_stack(args: &Vec<CString>, env: &Vec<CString>, auxv: &Vec<(u64, u64)>) -> Vec<u64> {
    let mut stack = Vec::new();
    macro_rules! push {
        ($x:expr) => {
            stack.push($x as u64)
        };
    }
    const NULL: u64 = 0;
    push!(args.len());
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
    extern "C" fn trail_func() {
        println!("From Rust!");
    }
    asm!(
        "mov rsp, {sp}",
        "mov rdx, {trail_func}",
        "jmp {entry_point}",
        entry_point = in(reg) entry_point as u64,
        sp = in(reg) sp as u64,
        trail_func = in(reg) trail_func as u64,
    );
    loop {}
}

fn get_fixed_auxv(
    base: *const u8,
    ehdr: &Elf64_Ehdr,
    entry_point: *const u8,
    input_path: *const u8,
) -> Vec<(u64, u64)> {
    let auxv: Vec<_> = (2_u64..=47)
        .into_iter()
        .filter_map(|r#type| unsafe {
            match libc::getauxval(r#type) {
                0 => None,
                value => match r#type {
                    libc::AT_PHDR => {
                        Some((r#type, base.wrapping_add(ehdr.e_phoff as usize) as u64))
                    }
                    libc::AT_PHNUM => Some((r#type, ehdr.e_phnum.into())),
                    libc::AT_PHENT => Some((r#type, ehdr.e_phentsize.into())),
                    libc::AT_ENTRY => Some((r#type, entry_point as u64)),
                    libc::AT_EXECFN => Some((r#type, input_path as u64)),
                    _ => Some((r#type, value)),
                },
            }
        })
        .collect();
    auxv
}

fn get_base(load_phdrs: Option<Vec<&Elf64_Phdr>>) -> *const u8 {
    let base = BASE.get_or_init(|| {
        let mem_range = load_phdrs
            .unwrap()
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
        base as u64
    });
    *base as *const u8
}

unsafe extern "C" fn sigsegv_handler(_signo: libc::c_int, info: *const libc::siginfo_t) {
    println!("SIGSEGV!\n\n");
    let foul_addr = info.as_ref().unwrap().si_addr() as u64;
    let base = get_base(None);
    let foul_addr = foul_addr - base as u64;
    let (_, phdrs) = parse(BYTES.get().unwrap());
    let ph = phdrs
        .iter()
        .filter(|ph| ph.p_type == libc::PT_LOAD)
        .find(|ph| (ph.p_vaddr..ph.p_vaddr + ph.p_memsz).contains(&foul_addr))
        .unwrap();
    mprotect_segment(base, ph, flags_to_prot(ph.p_flags))
}

fn parse<'a>(bytes: &'a [u8]) -> (&'a Elf64_Ehdr, &'a [Elf64_Phdr]) {
    let ehdr = &as_custom_slice::<Elf64_Ehdr>(bytes, 1)[0];
    let phdrs = as_custom_slice::<Elf64_Phdr>(&bytes[ehdr.e_phoff as usize..], ehdr.e_phnum.into());
    (ehdr, phdrs)
}

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: loader [program]...");
    let input_path = std::fs::canonicalize(input_path)?;
    let bytes = BYTES.get_or_init(|| std::fs::read(&input_path).unwrap());

    let (ehdr, phdrs) = parse(BYTES.get().unwrap());
    let load_phdrs_iter = phdrs.iter().filter(|ph| ph.p_type == libc::PT_LOAD);

    let base = get_base(Some(load_phdrs_iter.clone().collect()));

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

    load_phdrs_iter
        .clone()
        .for_each(|ph| unsafe { mprotect_segment(base, ph, Protection::empty()) });

    let args: Vec<_> = env::args()
        .skip(1)
        .map(|arg| CString::new(arg).unwrap())
        .collect();
    let env: Vec<_> = env::vars()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
        .collect();
    let auxv = get_fixed_auxv(base, ehdr, entry_point, args[0].as_ptr().cast());

    let stack_data = build_stack(&args, &env, &auxv);
    let stack_len = stack_data.len();

    const STACK_SIZE: usize = 10000;
    let mut stack: [u64; STACK_SIZE] = [0; STACK_SIZE];
    (0..=(stack_len - 1)).into_iter().rev().for_each(|i| {
        stack[STACK_SIZE - stack_len + i] = stack_data[i];
    });

    let act: libc::sigaction = libc::sigaction {
        sa_sigaction: sigsegv_handler as usize,
        sa_mask: unsafe { transmute([0_u64; 16]) },
        sa_flags: libc::SA_SIGINFO,
        sa_restorer: None,
    };

    unsafe {
        libc::sigaction(libc::SIGSEGV, &act as *const _, std::ptr::null_mut());
    }

    unsafe {
        jump(
            entry_point,
            stack.as_ptr().wrapping_add(STACK_SIZE - stack_len),
        )
    };
}
