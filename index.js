const config = require("./config.json");
const fs = require("fs");
const child_process = require("child_process");
const path = require("path");

// TODO convert this crap to makefile

var res = function(thePath) {
	return path.resolve(thePath).replace(/\\/g, '/');
};
var idaLogPath = res("idatemplog.txt");
var tailCommand = "tail";

var idaCommandPrefix = `${config.IDA_path}/idat64.exe -A -Tnintendo -L${idaLogPath}`;

// Executable format: AARCH64 v8A 64 little	default
// AARCH64:LE:64:v8A (1.4)
// Generic ARM v8.3-A Little endian instructions, Little endian data
// Use SwIPC for the rest of the extern functions
async function startGenSdkFuncs(game) {
	await new Promise(resolve => {
		console.log("------START GENERATING SDK FUNCS------");
		var cmd = `${idaCommandPrefix} -S\"${res("dumpsdkfuncs.py")} ${res("games/" + game + "/defs.txt")} ${res("games/" + game + "/defs.h")} ${res("bin/demumble.exe")}\" ${res("games/" + game + "/exefs/main")}`;
		console.log(cmd);
		var getSdkFuncsProcess = child_process.spawn(cmd, {
			shell: true,
		});

		var logOutput = child_process.spawn(tailCommand, ["-f", idaLogPath]);

		logOutput.stdout.on("data", function(data) {
			process.stdout.write(data.toString());
		});

		getSdkFuncsProcess.on('error', (error) => {
			console.error(error.message);
		});

		getSdkFuncsProcess.on("close", code => {
			console.log("------DONE GENERATING SDK FUNCS------");
			logOutput.kill("SIGINT");
			resolve();
		});
	});
}

async function startGenConfig(game) {
	await new Promise(resolve => {
		console.log("------START GENERATING CONFIG------");
		var mcsemaPythonPath = res("mcsema/Lib/site-packages/mcsema_disass-2.0-py3.8.egg/mcsema_disass/ida7/get_cfg.py");
		var cmd = `${idaCommandPrefix} -S\"${mcsemaPythonPath} --output ${"games/" + game + "/config.cfg"} --std-defs ${res("games/" + game + "/defs.txt")} --arch aarch64 --os linux --entrypoint nnMain\" ${res("games/" + game + "/exefs/main")}`;
		console.log(cmd);
		var genConfigProcess = child_process.spawn(cmd, {
			shell: true,
		});

		var logOutput = child_process.spawn(tailCommand, ["-f", idaLogPath]);

		logOutput.stdout.on("data", function(data) {
			process.stdout.write(data.toString());
		});

		genConfigProcess.on('error', (error) => {
			console.error(error.message);
		});

		genConfigProcess.on("close", code => {
			console.log("------DONE GENERATING CONFIG------");
			logOutput.kill("SIGINT");
			resolve();
		});
	});
}

async function startMcsema(game) {
	await new Promise(resolve => {
		console.log("------START MCSEMA------");
		var cmd = `${res("mcsema/bin/mcsema-lift-5.0.exe")} --platform linux --architecture aarch64 --cfg-path ${res("games/" + game + "/config.cfg")} --output-path ${res("games/" + game + "/bitcode.bc")}`;
		console.log(cmd);
		var mcsemaProcess = child_process.spawn(cmd, {
			shell: true,
		});

		mcsemaProcess.stdout.on("data", data => {
			console.log(data);
		});

		mcsemaProcess.stderr.on("data", data => {
			console.error(data);
		});

		mcsemaProcess.on('error', (error) => {
			console.error(error.message);
		});

		mcsemaProcess.on("close", code => {
			console.log("-----DONE MCSEMA------");
			resolve();
		});
	});
}

async function generateNativeExecutable(game, target) {
	await new Promise(resolve => {
		console.log("------START BUILDING NATIVE EXECUTABLE------");
		var nativeExecutableGenProcess;
		const binaryFolder = "./bin";
		if (target === "web") {
			nativeExecutableGenProcess = child_process.spawn(`emcc -O3 ${res(game + ".bc")} -o ${res(game + ".js")}`, {
				shell: true,
			});
		} else if (target === "native-64bit" || target === "native-32bit") {
			if (!fs.existsSync(binaryFolder)) {
				fs.mkdirSync(binaryFolder);
			}
			// https://llvm.org/docs/CommandGuide/llc.html
			nativeExecutableGenProcess = child_process.spawn(`${config.LLVM_path}/bin/llc -O=3 -obj= -o ${res(binaryFolder + "/maingamebinary.o")} --stats ${res(game + ".bc")}`, {
				shell: true,
			});
		}

		nativeExecutableGenProcess.stdout.on("data", data => {
			console.log(data);
		});

		nativeExecutableGenProcess.stderr.on("data", data => {
			console.error(data);
		});

		nativeExecutableGenProcess.on('error', (error) => {
			console.error(error.message);
		});

		nativeExecutableGenProcess.on("close", code => {
			console.log("-----DONE START BUILDING NATIVE EXECUTABLE------");
			var makefileProcess;
			if (target === "native-64bit") {
				console.log("-----START MAKE------");
				makefileProcess = child_process.spawn(`make ARCH=64`, {
					shell: true,
				});
			} else if (target === "native-32bit") {
				console.log("-----START MAKE------");
				makefileProcess = child_process.spawn(`make ARCH=32`, {
					shell: true,
				});
			}

			makefileProcess.stdout.on("data", data => {
				console.log(data);
			});

			makefileProcess.stderr.on("data", data => {
				console.error(data);
			});

			makefileProcess.on('error', (error) => {
				console.error(error.message);
			});

			nativeExecutableGenProcess.on("close", code => {
				console.log("-----DONE MAKE------");
				resolve();
			});
		});
	});
}

async function genGameExecutable(gameName) {
	await startGenSdkFuncs(gameName);
	await startGenConfig(gameName);
	// await startMcsema(gameName);
	// await generateNativeExecutable(gameName, "native-64bit");
}

genGameExecutable("smm2");