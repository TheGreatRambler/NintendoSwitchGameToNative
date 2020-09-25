const config = require("./config.json");
const child_process = require("child_process");

var gameName = "smm2";

// Use SwIPC for the rest of the extern functions
const genConfigProcess = child_process.spawn(config.IDA_path + "/ida64.exe", ["-S", "'" + config.mcsema_path + "/Lib/site-packages/mcsema_disass-2.0-py3.8.egg/mcsema_disass/ida7/get_cfg.py", "--output", "calc.cfg", "--log_file", "calc.log", "--arch", "aarch64", "--os", "linux", "--entrypoint", "nnMain'", "games/" + gameName + "/exefs/main"]);

genConfigProcess.stdout.on("data", data => {
	console.log(`stdout: ${data}`);
});

genConfigProcess.stderr.on("data", data => {
	console.log(`stderr: ${data}`);
});

genConfigProcess.on('error', (error) => {
	console.log(`error: ${error.message}`);
});

genConfigProcess.on("close", code => {
	console.log(`child process exited with code ${code}`);
});

const mcsemaProcess = child_process.spawn(config.mcsema_path + "/bin/mcsema-lift-5.0.exe", ["--os", "linux", "--arch", "amd64", "--cfg", "xz.cfg", "--output", "game.bc"]);

mcsemaProcess.stdout.on("data", data => {
	console.log(`stdout: ${data}`);
});

mcsemaProcess.stderr.on("data", data => {
	console.log(`stderr: ${data}`);
});

mcsemaProcess.on('error', (error) => {
	console.log(`error: ${error.message}`);
});

mcsemaProcess.on("close", code => {
	console.log(`child process exited with code ${code}`);
});