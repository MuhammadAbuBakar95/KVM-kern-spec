import subprocess, sys, json, os
import re
import sys
import struct
from shutil import copyfile

addr_lo = 0xffffffff81000000 # 0xffffffff81609000
addr_hi = 0xffffffff819a1000 # 0xffffffff8160c000
file_offset = 0x200000 # 0x809000
text_size = 0x9a1000 # 12288

def read_file(fname):
	with open(fname) as f:
		content = f.readlines()
	return [x.strip() for x in content]


def add_curr_pr_address(fname):
	p1 = subprocess.Popen(["llvm-nm", fname], stdout=subprocess.PIPE)
	p2 = subprocess.Popen(["grep", "tracking_enabled"], stdin=p1.stdout, stdout=subprocess.PIPE)
	out = p2.communicate()[0]
	with open("/home/muhammad/testing/debloating/dt_ita_addr", 'w') as fd:
		print hex(int(out.split()[0], 16))
		fd.write(struct.pack("Q", int(out.split()[0], 16)))
		

def get_func_names(fname, threshold):
	content = read_file(fname)
	stripped = map(lambda x : x.split(), content)
	func_names_is = map(lambda x : x[0], (filter(lambda x : (int(x[1]) <= 1000 and int(x[1]) > threshold), stripped)))
	func_names_oos = map(lambda x : x[0], (filter(lambda x : int(x[1]) <= threshold, stripped)))
	return func_names_is, func_names_oos

def create_copy(vmfile, suff):
	cpy = vmfile + suff
	copyfile(vmfile, cpy)
	return cpy
	
def get_symbol_info(vmfile, func_names_is, func_names_oos):
	p = subprocess.Popen(["objdump", "-dF", vmfile.strip()], stdout=subprocess.PIPE)
	output = p.communicate()[0]
	output = output.split('\n')

	work_section = False
	func_info = []
	func_names_is = set(func_names_is)
	func_names_oos = set(func_names_oos)
	to_exclude = ["total_mapping_size", "load_elf_binary", "chksum_update"]
	infunc = False
	init_section_list = []
	pattern = re.compile("([a-z0-9]+) <([_a-zA-Z0-9]+)> \(File Offset: ([a-z0-9]+)\):")
	for idx, line in enumerate(output):
		if line == "":
			infunc = False
			continue
		if work_section:
			toks = line.split("\t")
			if len(toks) >= 2:
				code_size = len(toks[1].split())
				if infunc:
					func_info[len(func_info) - 1][4].append(code_size)
				if line.find("_einittext") >= 0:
					init_section_list.append((line, line[:16], code_size))
		matched = pattern.match(line)
		if not matched:
			continue
		func_name = matched.group(2)
		if(func_name == "ud2_call"):
			global switch_ctx_offset
			switch_ctx_offset = int(matched.group(3), 16)
			continue
		address = int(matched.group(1), 16)
		is_is = -1
		if address < addr_lo:
			continue
		if address >= addr_hi:
			break
		work_section = True
		if func_name in func_names_is:
			is_is = True
		elif func_name in func_names_oos:
			is_is = False 
		else:
			continue
		infunc = True
		address = matched.group(1)
		offset = matched.group(3)
		func_info.append((func_name, address, offset, is_is, []))
	return func_info, init_section_list



vmfile = sys.argv[1]
ffile = sys.argv[2]
threshold = int(sys.argv[3])

add_curr_pr_address(vmfile)
func_names_is, func_names_oos = get_func_names(ffile, threshold)

print len(func_names_is), len(func_names_oos)
func_info, init_section_list = get_symbol_info(vmfile, func_names_is, func_names_oos)

temp = []
for tup in func_info:
	if tup[3] == False and tup in temp:
		print tup
	temp.append(tup)


print len(filter(lambda x : x[3] == False, func_info))
with open("/home/muhammad/testing/debloating/init_section_list", 'w') as fd:
	for line, address, size in init_section_list:
		# print line, address, size
		address = struct.pack("Q", int(address, 16))
		size = struct.pack("I", size)
		fd.write(address)
		fd.write(size)

with open(vmfile, "r+b") as fd:
	fd.seek(switch_ctx_offset)
	fd.write(chr(int("0F", 16)))
	fd.write(chr(int("0B", 16)))

to_store = []
iis = create_copy(vmfile, "_is")
oos = create_copy(vmfile, "_oos")

with open(iis, "r+b") as fd:
	for (func_name, address, offset, is_is, inst_sizes) in func_info:
		offset = int(offset, 16)
		fd.seek(offset)
		code = fd.read(sum(inst_sizes))
		fd.seek(offset)
		code_idx = 0
		if not is_is:
			for isize in inst_sizes:
				if isize == 1: 
					fd.write(code[code_idx])
					code_idx += 1
					continue
				for x in xrange(isize/2):
					fd.write(chr(int("0F", 16)))
					fd.write(chr(int("0B", 16)))
					code_idx += 2
				if isize % 2:
					fd.write(chr(int("90", 16)))
					code_idx += 1
			# if inst_sizes[0] == 1:
			# 	continue
			# fd.write(chr(int("0F", 16)))
			# fd.write(chr(int("0B", 16)))
		to_store.append((func_name, address, code, is_is, inst_sizes))

with open(oos, "r+b") as fd:
	for (func_name, address, offset, is_is, inst_sizes) in func_info:
		offset = int(offset, 16)
		fd.seek(offset)
		code = fd.read(sum(inst_sizes))
		fd.seek(offset)
		code_idx = 0
		if is_is:
			for isize in inst_sizes:
				if isize == 1: 
					fd.write(code[code_idx])
					code_idx += 1
					continue
				for x in xrange(isize/2):
					fd.write(chr(int("0F", 16)))
					fd.write(chr(int("0B", 16)))
					code_idx += 2
				if isize % 2:
					fd.write(chr(int("90", 16)))
					code_idx += 1
		# to_store.append((func_name, address, code, is_is, inst_sizes))

fd = open(vmfile, 'r+b')

with open("/home/muhammad/testing/debloating/dt_func_code_original", 'w') as fd2:
	fd.seek(file_offset)
	for i in xrange(text_size):
		byte = fd.read(1)
		fd2.write(byte)

fd.close()

fd = open(iis, 'r+b')

with open("/home/muhammad/testing/debloating/dt_func_code_is", 'w') as fd2:
	# fd.seek(0x200000)
	fd.seek(file_offset)
	for i in xrange(text_size):
		byte = fd.read(1)
		fd2.write(byte)

fd.close()

fd = open(oos, 'r+b')

with open("/home/muhammad/testing/debloating/dt_func_code_oos", 'w') as fd2:
	# fd.seek(0x200000)
	fd.seek(file_offset)
	for i in xrange(text_size):
		byte = fd.read(1)
		fd2.write(byte)
		# print hex(ord(byte))

fd.close()

with open("/home/muhammad/testing/debloating/dt_func_info_is", 'w') as fd:
	for (func_name, address, code, is_is, inst_sizes) in to_store:
		address = struct.pack("Q", int(address, 16))
		code_size = struct.pack("I", len(code))
		strlen = struct.pack("I", len(func_name))
		inst_size0 = struct.pack("I", inst_sizes[0])
		inst_size1 = struct.pack("I", inst_sizes[1])
		new_code = ""
		fd.write(strlen)
		fd.write(func_name)
		fd.write(address)
		fd.write(code_size)
		fd.write(inst_size0)
		fd.write(inst_size1)		
		fd.write(code)
