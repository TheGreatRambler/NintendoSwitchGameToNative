const config = require("./config.json");
const fs = require("fs");
const child_process = require("child_process");
const path = require("path");

// TODO convert this crap to makefile

var res = function(thePath) {
	return path.resolve(thePath).replace(/\\/g, '/');
};

var gameName = "smm2";
var idaCommandPrefix = `${config.IDA_path}/ida64.exe -Tnintendo -L${res("idalog.txt")}`;

// Executable format: AARCH64 v8A 64 little	default
// AARCH64:LE:64:v8A (1.4)
// Generic ARM v8.3-A Little endian instructions, Little endian data
// Use SwIPC for the rest of the extern functions
async function startGenSdkFuncs(game) {
	console.log("------START GENERATING SDK FUNCS------");
	var cmd = `${idaCommandPrefix} -S\" ${res("dumpsdkfuncs.py")} ${res("games/" + game + "/defs.txt")} ${res("idascriptlog.txt")}\" ${res("games/" + game + "/exefs/main")}`;
	console.log(cmd);
	var getSdkFuncsProcess = child_process.spawn(cmd, {
		shell: true,
	});

	getSdkFuncsProcess.stdout.on("data", data => {
		console.log(data);
	});

	getSdkFuncsProcess.stderr.on("data", data => {
		console.error(data);
	});

	getSdkFuncsProcess.on('error', (error) => {
		console.error(error.message);
	});

	getSdkFuncsProcess.on("close", code => {
		console.log("------DONE GENERATING SDK FUNCS------");
		return;
	});
}

async function startGenConfig(game) {
	console.log("------START GENERATING CONFIG------");
	var mcsemaPythonPath = config.mcsema_path + "/Lib/site-packages/mcsema_disass-2.0-py3.8.egg/mcsema_disass/ida7/get_cfg.py";
	var cmd = `${idaCommandPrefix} -S\"${mcsemaPythonPath} --output ${res(game + ".cfg")} --std-defs ${res("games/" + game + "/defs.txt")} --arch aarch64 --os linux --entrypoint nnMain\" ${res("games/" + game + "/exefs/main")}`;
	console.log(cmd);
	var genConfigProcess = child_process.spawn(cmd, {
		shell: true,
	});

	genConfigProcess.stdout.on("data", data => {
		console.log(data);
	});

	genConfigProcess.stderr.on("data", data => {
		console.error(data);
	});

	genConfigProcess.on('error', (error) => {
		console.error(error.message);
	});

	genConfigProcess.on("close", code => {
		console.log("------DONE GENERATING CONFIG------");
		return;
	});
}

async function startMcsema(game) {
	console.log("------START MCSEMA------");
	var cmd = `${config.mcsema_path}/bin/mcsema-lift-5.0.exe --platform linux --architecture aarch64 --cfg-path ${res(game + ".cfg")} --output-path ${res(game + ".bc")}`;
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
	});
}

async function generateNativeExecutable(game, target) {
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
			return;
		});
	});
}

async function genGameExecutable(gameName) {
	await startGenSdkFuncs(gameName);
	// await startGenConfig(gameName);
	// await startMcsema(gameName);
	// await generateNativeExecutable(gameName, "native-64bit");
}

genGameExecutable("smm2");