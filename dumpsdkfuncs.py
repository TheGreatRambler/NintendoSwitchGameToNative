import idautils
import idaapi
import idc
import subprocess
import pycparser
import ida_typeinf
import ida_nalt

sdk_funcs_file = open(idc.ARGV[1], "w")
sdk_funcs_header = open(idc.ARGV[2], "w")
# Uses demumble as a drop in replacment
cppfilt_path = idc.ARGV[3]

print "Wait for auto analysis"
idc.auto_wait()

# Disable terminal opening up
# https://stackoverflow.com/a/23924771/9329945
if hasattr(subprocess, 'STARTUPINFO'):
# Windows
	si = subprocess.STARTUPINFO()
	si.dwFlags |= subprocess.STARTF_USESHOWWINDOW   
	# The following is the initialized default, but
	# setting it explicitly is self-documenting.
	si.wShowWindow = subprocess.SW_HIDE 
else: 
# POSIX
	si = None

print "Starting analysis"
current_index = 0
for ea in idautils.Functions():
	flags = idc.GetFunctionFlags(ea)
	func_name = idc.get_func_name(ea)
	if (current_index % 1000 == 0):
		print "Processing function %d" % current_index
	if flags & FUNC_THUNK and not func_name.startswith("sub_") and not func_name.startswith("j__ZdlPv") and not "null" in func_name:
		# Revert weird designations
		# could also use ida_funcs.set_func_name_if_jumpfunc(ea, None)
		func_name = func_name.replace("j_", "")
		func_name = func_name.replace("_0", "")
		func_name = func_name.replace("_1", "")
		funcdata = ida_typeinf.func_type_data_t()
		tinfo = ida_typeinf.tinfo_t();
		ida_nalt.get_tinfo(tinfo, ea);
		tinfo.get_func_details(funcdata)
		if (flags & FUNC_NORET):
			retcode = ''
		else:
			retcode = 'N'
		mcsema_def = ("%s %d C %s" % (func_name, funcdata.size(), retcode)).strip()
		sdk_funcs_file.write(mcsema_def + '\n')
		
		demangled_str = subprocess.check_output([cppfilt_path, func_name], shell=True, startupinfo=si).strip()
		sdk_funcs_header.write(demangled_str + '\n')
	current_index += 1
sdk_funcs_file.close()
sdk_funcs_header.close()

print "Done analysis!"
idc.Exit(0)