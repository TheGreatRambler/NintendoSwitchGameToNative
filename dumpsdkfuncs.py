import idautils
import idaapi
import idc

sdk_funcs_file = open(idc.ARGV[1], "w")
script_log_file = open(idc.ARGV[2], "w")

def log(str):
	script_log_file.write(str + "\n")
	script_log_file.flush()

log("Wait for auto analysis")
idc.auto_wait()

log("Starting analysis")
for ea in idautils.Functions():
	str = idc.get_func_name(ea)
	if str:
		sdk_funcs_file.write(str + "\n")
sdk_funcs_file.close()

log("Done analysis!")
script_log_file.close()
idc.Exit(0)