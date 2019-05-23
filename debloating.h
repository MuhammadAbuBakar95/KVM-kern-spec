#ifndef KVM_UNIFDEF_H
#define KVM_UNIFDEF_H

#ifdef __i386__
#ifndef CONFIG_X86_32
#define CONFIG_X86_32 1
#endif
#endif

#ifdef __x86_64__
#ifndef CONFIG_X86_64
#define CONFIG_X86_64 1
#endif
#endif

#if defined(__i386__) || defined (__x86_64__)
#ifndef CONFIG_X86
#define CONFIG_X86 1
#endif
#endif

#ifdef __PPC__
#ifndef CONFIG_PPC
#define CONFIG_PPC 1
#endif
#endif

#ifdef __s390__
#ifndef CONFIG_S390
#define CONFIG_S390 1
#endif
#endif

#endif

#include <linux/kvm_host.h>
#include <asm/vmx.h>
#include "x86.h"
#include "mmu.h"

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <asm/mman.h>

#include "timing.h"
#include "printing.h"

#define dt_fpath_is "/home/muhammad/testing/debloating/dt_func_info_is"
#define dt_fpath_oos "/home/muhammad/testing/debloating/dt_func_info_oos"
#define dt_fpath_qemu_addrs "/home/muhammad/testing/debloating/qemu_addrs"
#define dt_fpath_in_target_app "/home/muhammad/testing/debloating/dt_ita_addr"
#define dt_fpath_init_section_list "/home/muhammad/testing/debloating/init_section_list"
#define dt_fpath_addr_log "/home/muhammad/testing/debloating/addr_log"
#define switch_context_ud2_addr 0xffffffff8102b4b0
#define switch_context_ret_addr 0xffffffff8102b4c6
#define text_section_offset 0xffffffff81000000 // 0xffffffff81609000
#define text_section_size  0x9a1000 // 12288 // 0x9a0a1b
#define INIT_ARRAY_SIZE 5000
#define num_ts_frames 2465

bool HAS_SWITCHED = false;
bool HAS_HANDLED = false;
bool IS_TRACKED_PROC = false;
char ud2_buffer[] = {0xf,0xb};

struct file * file_open(const char * path, int flags, int rights)  {
    struct file * filp = NULL;
    mm_segment_t oldfs;
    int err = 0;
    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        dt_printk("file_open : failed to open file : %d\n", err);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) {
    filp_close(file, NULL);
}

int file_read(struct file * file, unsigned char * data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;
    oldfs = get_fs();
    set_fs(get_ds());
    ret = kernel_read(file, data, size, &file->f_pos);
    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned char *data, unsigned int size)  {
    mm_segment_t oldfs;
    int ret;
    oldfs = get_fs();
    set_fs(get_ds());
    ret = kernel_write(file, data, size, &file->f_pos);
    set_fs(oldfs);
    return ret;
}

unsigned long dt_get_gpa(struct kvm_vcpu *vcpu, unsigned long addr) {
    struct x86_exception e;
    return vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, 0, &e);    
}

unsigned long dt_get_gfn(struct kvm_vcpu *vcpu, unsigned long addr) {
    unsigned long gfn;
    gpa_t gpaddr;
    struct x86_exception e;
    gpaddr = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, 0, &e);
    gfn = gpaddr >> PAGE_SHIFT;
    return gfn;   
}

unsigned long dt_get_hva(struct kvm_vcpu *vcpu, unsigned long addr) {
    unsigned long hva;
    gpa_t gpaddr;
    struct x86_exception e;
    gpaddr = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, 0, &e);
    hva = gfn_to_hva(vcpu->kvm, gpaddr >> PAGE_SHIFT);
    hva += gpaddr & (~PAGE_MASK);
    return hva;
}
 
struct kvm_memory_slot * dt_get_memslot(struct kvm_vcpu *vcpu, unsigned long addr) {
    struct x86_exception e;
    gpa_t gpaddr = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, 0, &e);
    return gfn_to_memslot(vcpu->kvm, gpaddr >> PAGE_SHIFT); 
}

void dt_copy_to_user(struct kvm_vcpu *vcpu, unsigned long addr, char * buffer, int size) {
    int copy_size;
    unsigned long hva;
    while(size > 0) {
        hva = dt_get_hva(vcpu, addr);
        copy_size = min((int) (PAGE_SIZE - (addr & (~PAGE_MASK))), size);
        copy_to_user((void *) hva, (void *) buffer, copy_size);
        size -= copy_size;
        addr += copy_size;
        buffer += copy_size;
    }
}

void dt_copy_from_user(struct kvm_vcpu *vcpu, unsigned long addr, char * buffer, int size) {
    int copy_size;
    unsigned long hva;
    while(size > 0) {
        hva = dt_get_hva(vcpu, addr);
        copy_size = min((int) (PAGE_SIZE - (addr & (~PAGE_MASK))), size);
        copy_from_user((void *) buffer, (void *) hva, copy_size);

        size -= copy_size;
        addr += copy_size;
        buffer += copy_size;
    }
}

int tracked_proc = -1;
int num = 0;
unsigned long ita_addr  = 0;
char curr_proc_name[100];

void check_curr_proc(struct kvm_vcpu * vcpu) {    
    copy_from_user((void *) &tracked_proc, (void *) dt_get_hva(vcpu, ita_addr ), 4);
    copy_from_user((void *) curr_proc_name, (void *) dt_get_hva(vcpu, 0xffffffff82426860), 4);
    if(!strncmp(curr_proc_name, "test", 4)) {
        tracked_proc = 1;
    }
    IS_TRACKED_PROC = (tracked_proc > 0);
    set_timing(IS_TRACKED_PROC);
}

struct func_node {
    char * name;
    unsigned long address;
    int code_size;
    char * code;
    int freq, freq_entry, inst_size1, inst_size2;
};

struct func_node * dt_init_func_node(char * name, unsigned long address, int code_size, int inst_size1, int inst_size2, char * code) {
    struct func_node * fn = kmalloc(sizeof(struct func_node), GFP_KERNEL);
    fn->name = name;
    fn->address = address;
    fn->code_size = code_size;
    fn->code = code;
    fn->inst_size1 = inst_size1;
    fn->inst_size2 = inst_size2;
    fn->freq = 0;
    fn->freq_entry = 0;
    return fn;
}

enum state {
    IS,
    OOS
};

enum state curr_state = IS;
struct func_node ** fn_array_is;
int fn_array_is_size = 0;

struct func_node ** fn_array_oos;
int fn_array_oos_size = 0;


unsigned long init_section_list[500];
int num_init_insts = 0;

int fd_is, fd_oos, fd_original;
unsigned long is_us_addr, oos_us_addr, original_us_addr;

struct file * fd_log;

struct file_desc_attrs {
    struct file * fd;
    bool modified;
};

struct file_desc_attrs init_fda(struct file * fd) {
    struct file_desc_attrs fda;
    fda.fd = fd;
    fda.modified = false;
    return fda;
}

extern struct gfn_range;
int tgr_size = 0;
struct gfn_range tracked_gfn_ranges[num_ts_frames];
struct gfn_range orig_gfn_ranges[1];

struct file_desc_attrs fdas[3];

struct timeval mmap_time;
struct timeval zap_time;
struct timeval total_time;
int num_changes_in_scope = 0;

void dt_init_times(void) {
    init_time(&mmap_time);
    init_time(&zap_time);
    init_time(&total_time);
    num_changes_in_scope = 0;
}

void check_and_print(struct kvm_vcpu * vcpu) {
    int val;
    copy_from_user((char *) &val, (char *) dt_get_hva(vcpu, 0xffffffff82426840), 4);
    if(val != 'y') return;
    // for(i = 0; i < fn_array_is_size; i++) {
    //     dt_printk("%s %d,%d", fn_array_is[i]->name, fn_array_is[i]->freq, fn_array_is[i]->freq_entry);
    //     fn_array_is[i]->freq = 0;
    //     fn_array_is[i]->freq_entry = 0;   
    // }
    val = 'n';
    copy_to_user((char *) dt_get_hva(vcpu, 0xffffffff82426840), (char *) &val, 4);
    print_time("total zap_time : ", zap_time);
    dt_printk("num_changes_in_scope %d\n", num_changes_in_scope);
    dt_init_times();
    print_time("total zap_time : ", zap_time);
    dt_printk("num_changes_in_scope %d\n", num_changes_in_scope);
}

void dt_init_log(void) {
    fd_log = filp_open(dt_fpath_addr_log, O_CREAT | O_TRUNC | O_WRONLY, 0);
    dt_printk("fd_log is %p", fd_log);
}

void write_to_log(unsigned long addr) {
    file_write(fd_log, (char *) &addr, 8);
}

bool dt_do_safe_read(struct file * fd, char * buffer, int size) {
    int bytes_read;
    bytes_read = file_read(fd, buffer, size);
    return bytes_read == size;
}

struct func_node * dt_parse_token(struct file * fd) {
    char buffer[8];
    int namelen, code_size, inst_size1, inst_size2;
    char * name, * code;
    unsigned long address;
    if(!dt_do_safe_read(fd, buffer, 4)) {
        return NULL;
    }
    namelen = *(int *) buffer;
    name = kmalloc(sizeof(char) * (namelen + 1), GFP_KERNEL);
    if(!dt_do_safe_read(fd, name, namelen)) {
        return NULL;
    }
    name[namelen] = '\0';
    if(!dt_do_safe_read(fd, buffer, 8)) {
        return NULL;
    }
    address = *(long *) buffer;
    if(!dt_do_safe_read(fd, buffer, 4)) {
        return NULL;
    }
    code_size = *(int *) buffer;

    if(!dt_do_safe_read(fd, (char *) &inst_size1, 4)) {
        return NULL;
    }
    if(!dt_do_safe_read(fd, (char *) &inst_size2, 4)) {
        return NULL;
    }
    dt_printk("dt_parse_token : namelen -> %d, name -> %s address -> 0x%lx code_size -> %d, inst_size1 %d, inst_size2 %d\n", namelen, name, address, code_size, inst_size1, inst_size2);
    code = kmalloc(sizeof(char) * code_size, GFP_KERNEL);
    if(!dt_do_safe_read(fd, code, code_size)) {
        return NULL;    
    }
    return dt_init_func_node(name, address, code_size, inst_size1, inst_size2, code);
}

void set_fn_tracked_frames(struct kvm_vcpu * vcpu, bool * tracked_gfns, struct func_node * fn) {
    unsigned long addr = dt_get_gpa(vcpu, fn->address);
    int size = fn->code_size;
    int frag_size;
    while(size > 0) {
        tracked_gfns[(addr >> PAGE_SHIFT) - 4096] = true;    
        frag_size = min((int) (PAGE_SIZE - (addr & (~PAGE_MASK))), size);
        addr += frag_size;
        size -= frag_size;
    }   
}

void init_tgr(bool * tracked_gfns) {
    int start_idx, end_idx, i;
    start_idx = -1;
    for(i = 0; i < num_ts_frames; i++) {
        if(tracked_gfns[i]) {
            if(start_idx < 0) start_idx = i;
            continue;
        }
        if(start_idx < 0) continue;
        end_idx = i - 1;
        tracked_gfn_ranges[tgr_size].start_idx = start_idx;
        tracked_gfn_ranges[tgr_size].end_idx = end_idx;
        tgr_size++;
        start_idx = -1;
    }
    for(i = 0; i < tgr_size; i++) {
        dt_printk("%d. start_idx %d, end_idx %d", i, tracked_gfn_ranges[i].start_idx, tracked_gfn_ranges[i].end_idx);
    }
    dt_printk("tgr_size is %d\n", tgr_size);
}

int dt_load_mem(struct kvm_vcpu * vcpu, char * fname, struct func_node ** fn_array) {
    struct file * fd;
    struct func_node * fn;
    int fn_array_size = 0, i;
    bool tracked_gfns[num_ts_frames];
    for(i = 0; i < num_ts_frames; i++) 
        tracked_gfns[i] = false;
    fd = filp_open(fname, O_RDONLY, 0);
    dt_printk("reading file  %s\n", fname);

    if(fd < 0) {
        dt_printk("dt_load_mem : failed to open file %s\n", fname);
        return fn_array_size;
    }
    while(true) {
        fn = dt_parse_token(fd);
        if(!fn) break;
        if(fn_array_size >= INIT_ARRAY_SIZE) {
            dt_printk("--------------------------------> size is greater than INIT_ARRAY_SIZE\n");
            return fn_array_size;
        }
        fn_array[fn_array_size] = fn;
        fn_array_size++;
        set_fn_tracked_frames(vcpu, tracked_gfns, fn);
    }
    file_close(fd);
    init_tgr(tracked_gfns);
    orig_gfn_ranges[0].start_idx = 0;
    orig_gfn_ranges[0].end_idx = num_ts_frames;
    return fn_array_size;
}

void dt_load_hva_addrs(void) {
    struct file * fd = filp_open(dt_fpath_qemu_addrs, O_RDONLY, 0);
    if(fd < 0) {
        dt_printk("dt_load_hva_addrs : failed to open file %s\n", dt_fpath_qemu_addrs);
        return;
    }    
    if(!dt_do_safe_read(fd, (char *) &fd_is, 4)) {
        return;
    }
    if(!dt_do_safe_read(fd, (char *) &fd_oos, 4)) {
        return;
    }
    if(!dt_do_safe_read(fd, (char *) &fd_original, 4)) {
        return;
    }
    fdas[0] = init_fda(fdget(fd_is).file);
    fdas[1] = init_fda(fdget(fd_oos).file);
    fdas[2] = init_fda(fdget(fd_original).file);        
    
    dt_printk("%d fd_is %d fd_oos %d fd_original %p %p %p\n", fd_is, fd_oos, fd_original, fdget(fd_is).file, fdget(fd_oos).file, fdget(fd_original).file);

    if(!dt_do_safe_read(fd, (char *) &is_us_addr, 8)) {
        return;
    }
    if(!dt_do_safe_read(fd, (char *) &oos_us_addr, 8)) {
        return;
    }
    if(!dt_do_safe_read(fd, (char *) &original_us_addr, 8)) {
        return;
    }
    dt_printk("%lx is_us_addr %lx oos_us_addr %lx\n", is_us_addr, oos_us_addr, original_us_addr);
}

void dt_load_init_section_list(void) {
    char buffer[8];
    struct file * fd = filp_open(dt_fpath_init_section_list, O_RDONLY, 0);
    if(fd < 0) {
        dt_printk("dt_load_init_section_list : failed to open file %s\n", dt_fpath_init_section_list);
        return;
    }        
    while(true) {
        if(!dt_do_safe_read(fd, buffer, 8)) {
            break;
        }
        init_section_list[num_init_insts] = *(long *) buffer;
        num_init_insts++;
        // read useless integer
        if(!dt_do_safe_read(fd, buffer, 4)) {
            break;
        }
    }
    dt_printk("num_init_insts %d", num_init_insts);
    file_close(fd);
}

void dt_load_ita_addr(void) {
    char buffer[8];
    struct file * fd = filp_open(dt_fpath_in_target_app, O_RDONLY, 0);
    if(fd < 0) {
        dt_printk("dt_load_ita_addr : failed to open file %s\n", dt_fpath_in_target_app);
        return;
    }        
    dt_do_safe_read(fd, buffer, 8);
    ita_addr = *(long *) buffer;
    dt_printk("ita_addr is %lx\n", ita_addr);
    file_close(fd);
}

void dt_initialize(struct kvm_vcpu * vcpu) {
    unsigned long foi;
    dt_printk("dt_initialize\n");
    fn_array_is = kmalloc(sizeof(struct func_node) * INIT_ARRAY_SIZE, GFP_KERNEL);
    fn_array_oos = kmalloc(sizeof(struct func_node) * INIT_ARRAY_SIZE, GFP_KERNEL);
    fn_array_is_size = dt_load_mem(vcpu, dt_fpath_is, fn_array_is);
    // fn_array_oos_size = dt_load_mem(vcpu, dt_fpath_oos, fn_array_oos);
    dt_load_init_section_list();
    dt_load_ita_addr();
    dt_load_hva_addrs();
    dt_init_times();
    dt_init_log();

    dt_printk("%ld -> start gfn : %ld end gfn\n", dt_get_gfn(vcpu, text_section_offset), dt_get_gfn(vcpu, text_section_offset + text_section_size));
    foi = dt_get_gfn(vcpu, 0xffffffff815d69c0);
    dt_printk("frame of interest is %ld idx %ld", foi, foi - 4096);
}

struct func_node * dt_get_fnode(unsigned long address, struct func_node ** fn_array, unsigned lo, unsigned hi) {
    unsigned mid; struct func_node * fn;
    if(lo == hi) return NULL;
    mid = lo + (hi - lo)/2;
    fn = fn_array[mid];
    if(address >= fn->address && address < (fn->address + fn->code_size)) return fn;
    if(address < fn->address) return dt_get_fnode(address, fn_array, lo, mid);
    else return dt_get_fnode(address, fn_array, mid + 1, hi);
}

unsigned long dt_get_return_addr(struct kvm_vcpu * vcpu, unsigned long stackp) {
    char buffer[8];
    int ptr_size = sizeof(unsigned long);
    dt_copy_from_user(vcpu, stackp, buffer, ptr_size);  
    return *(long *) &buffer;
}

bool init_modified = false;

bool dt_init_insts_changed(struct kvm_vcpu * vcpu) {
    unsigned char buffer[5];
    if(init_modified) return false;
    copy_from_user((void *) buffer, (void *) dt_get_hva(vcpu, init_section_list[0]), 5);
    if(buffer[0] != 0xe9) {
        dt_printk("dt_init_insts_changed\n");
        init_modified = true;
        return true;
    }
    return false;
}

void set_modified(struct file * next_fd) {
    int i;
    for(i = 0; i < 3; i++) {
        if(fdas[i].fd == next_fd)
            fdas[i].modified = true;
    }
}

bool should_modify(struct kvm_vcpu * vcpu, struct file * next_fd) {
    int i;
    if(dt_init_insts_changed(vcpu)) return true;
    if(!init_modified) return false;
    for(i = 0; i < 3; i++) {
        if(fdas[i].fd == next_fd && !fdas[i].modified) return true;
    }
    return false;
}

int get_kernel_state(struct file * fd) {
    if(fd == fdget(fd_original).file)
        return 0;
    else if(fd == fdget(fd_is).file)
        return 1;
    else 
        return 2;
}


bool dt_can_handle(struct kvm_vcpu *vcpu, unsigned long instp) {
    char buffer[2];
    if(instp < text_section_offset || instp >= text_section_offset + text_section_size)
        return false;
    copy_from_user(buffer, (void *) dt_get_hva(vcpu, instp), 2);
    return buffer[0] == ud2_buffer[0] && buffer[1] == ud2_buffer[1];
}

bool stopped = false;

void cs_mmap(struct file * fd, unsigned long addr, unsigned long size) {
    unsigned long populate;
    do_mmap(fd, addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, 0, 0, &populate, NULL);
    // print_time("time spent in mmap", mmap_time);
    // num_changes_in_scope++;
    // dt_printk("num_changes_in_scope %d\n", num_changes_in_scope);    
}

u64 usa_time = 0;

void cs_usa(struct kvm_vcpu * vcpu, int next_state, struct kvm_memory_slot * slot, struct gfn_range * gr, int gr_size) {
    gfn_t start_gfn, end_gfn;
    u64 start_t, diff_t;
    start_t = get_time();
    
    start_gfn = dt_get_gfn(vcpu, text_section_offset);
    end_gfn = dt_get_gfn(vcpu, text_section_offset + text_section_size);
    dt_change_pfns(vcpu, next_state, slot, gr, gr_size);

    diff_t = get_time_from(start_t);
    usa_time += diff_t;
    dt_printk("diff_t is %lld, total usa_time is %lld", diff_t, usa_time);
    num_changes_in_scope++;
    dt_printk("num changes in scope %d\n", num_changes_in_scope);
}

void dt_change_scope(struct kvm_vcpu * vcpu, struct file * fd, unsigned long next_us_addr, struct gfn_range * gr, int gr_size) {
    char buffer[num_init_insts][5];
    int i;
    struct kvm_memory_slot * slot;
    bool sm = should_modify(vcpu, fd);
    if(sm) {
        for(i = 0; i < num_init_insts; i++) {
            copy_from_user((void *) buffer[i], (void *) dt_get_hva(vcpu, init_section_list[i]), 5);
        }
    }

    slot = dt_get_memslot(vcpu, text_section_offset);
    if(!next_us_addr) {
        cs_mmap(fd, slot->userspace_addr + 0xf00000, text_section_size);
    } else {
        slot->userspace_addr = next_us_addr;
        cs_usa(vcpu, get_kernel_state(fd), slot, gr, gr_size);
        // cs_usa(vcpu, get_kernel_state(fd), slot, orig_gfn_ranges, 1);
    }

    if(sm) {
        for(i = 0; i < num_init_insts; i++) {
            copy_to_user((void *) dt_get_hva(vcpu, init_section_list[i]), (void *) buffer[i], 5);
        }
        set_modified(fd);
    }
    HAS_SWITCHED = true;
}
int num_ud2_insts = 0;
bool dt_handle_undefined(struct kvm_vcpu * vcpu, unsigned long instp) {
    unsigned long next_us_addr;
    struct func_node * fn, ** fn_array;
    int fn_array_size;
    struct file * next_fd;
    struct timeval tv;
    start_time(&tv);
    fn_array = fn_array_is;
    fn_array_size = fn_array_is_size;
    fn = dt_get_fnode(instp, fn_array, 0, fn_array_size);
    if(!fn) {
        dt_printk("not found %lx", instp);
        return false;
    }
    if(curr_state == IS) {
        next_fd = fdget(fd_oos).file;
        next_us_addr = oos_us_addr;
    }
    else {
        next_fd = fdget(fd_is).file;
        next_us_addr = is_us_addr;
    }
    fn->freq++;
    if(fn->address == instp) fn->freq_entry++;
    write_to_log(instp);
    dt_change_scope(vcpu, next_fd, next_us_addr, tracked_gfn_ranges, tgr_size);
    curr_state = (curr_state + 1) % 2;
    num_ud2_insts++;
    return true;
}

bool dt_handle_profiling(struct kvm_vcpu * vcpu, unsigned long instp) {
    struct func_node * fn, ** fn_array;
    int fn_array_size;
    fn_array = fn_array_is;
    fn_array_size = fn_array_is_size;
    fn = dt_get_fnode(instp, fn_array, 0, fn_array_size);
    if(!fn) {
        dt_printk("not found %lx", instp);
        return false;
    }
    fn->freq++;
    if(fn->address == instp) {
        fn->freq_entry++;
        dt_printk("dt_handle_profiling : handling function %s %lx\n", fn->name, instp);
        copy_to_user((char *) dt_get_hva(vcpu, fn->address), fn->code, 2);
        copy_to_user((char *) dt_get_hva(vcpu, fn->address + fn->inst_size1), ud2_buffer, 2);
    } else if(fn->address + fn->inst_size1 == instp) {
        copy_to_user((char *) dt_get_hva(vcpu, fn->address), ud2_buffer, 2);
        copy_to_user((char *) dt_get_hva(vcpu, fn->address + fn->inst_size1), fn->code + fn->inst_size1, 2);
    } else {
        return false;
    }
    return true;
}
bool in_original = true;
int num_switch_ctx_insts = 0;
bool dt_handle_switch_ctx(struct kvm_vcpu * vcpu, unsigned long instp) {
    struct file * next_fd;
    unsigned long next_us_addr;
    if(instp == switch_context_ud2_addr) {
        kvm_register_write(vcpu, VCPU_REGS_RIP, switch_context_ret_addr);
        if(tracked_proc > 0 && in_original) {
            if(curr_state == IS) {
                next_fd = fdget(fd_is).file;
                next_us_addr = is_us_addr;
            } else {
                next_fd = fdget(fd_oos).file;
                next_us_addr = oos_us_addr;
            }
            in_original = false;
            dt_change_scope(vcpu, next_fd, next_us_addr, orig_gfn_ranges, 1);
            num_switch_ctx_insts++;
        } else if(tracked_proc <= 0 && !in_original) {
            next_fd = fdget(fd_original).file;
            next_us_addr = original_us_addr;
            in_original = true;
            dt_change_scope(vcpu, next_fd, next_us_addr, orig_gfn_ranges, 1);
            num_switch_ctx_insts++;
        }
    } else {
        return false;
    }
    return true;
}

bool dt_handle_exception(struct kvm_vcpu * vcpu, unsigned long instp) {
    if(!dt_can_handle(vcpu, instp))
        return false;
    if(instp == 0xfd099) // early hardware exceptions
        return false;
    if(stopped)
        return false;
    check_curr_proc(vcpu);
    check_and_print(vcpu);
    if(!fn_array_is_size) dt_initialize(vcpu);
    HAS_HANDLED = dt_handle_switch_ctx(vcpu, instp) || /*dt_handle_profiling(vcpu, instp);*/ dt_handle_undefined(vcpu, instp);
    return HAS_HANDLED;
}