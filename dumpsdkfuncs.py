import argparse
import idautils
import idaapi
import idc

parser = argparse.ArgumentParser()

parser.add_argument(
	"--sdk_funcs",
	type = argparse.FileType('w'),
	default = sys.stdout,
	help = "Print out sdk function definitions for McSema.")

parser.add_argument(
	"--function_start",
	type = int,
	help = "Define function start.")

args = parser.parse_args(args = idc.ARGV[1: ])

print "Wait for auto analysis"
idc.auto_wait()

print "Starting analysis"
for ea in idautils.Functions():
	str = idc.get_func_name(ea)
	if str:
		args.sdk_funcs.write(str + "\n")
	args.sdk_funcs.close()

print "Done analysis!"
idc.qexit(0)