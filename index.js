const config        = require("./config.json");
const fs            = require("fs");
const child_process = require("child_process");
const path          = require("path");

// TODO convert this crap to makefile

var gameName         = "smm2";
var idaCommandPrefix = config.IDA_path + "/ida64.exe -Tnintendo -Lidalog.txt -c";

function getCommandLineChildProcess(string) {
	console.log(string);
	var arr = string.split(" ");
	return child_process.spawn(arr[0], arr.splice(0, 1));
}

// Executable format: AARCH64 v8A 64 little	default
// AARCH64:LE:64:v8A (1.4)
// Generic ARM v8.3-A Little endian instructions, Little endian data
// Use SwIPC for the rest of the extern functions
async function startGenSdkFuncs(game) {
	console.log("------START GENERATING SDK FUNCS------");
	var getSdkFuncsProcess = getCommandLineChildProcess("/ida64.exe", ["-Tnintendo", "-Lidalog.txt", "-c", "-S\"" + path.resolve("dumpsdkfuncs.py") + " --std-defs games/" + game + "/defs.txt --function_start 7100000000\"", path.resolve("games/" + game + "/exefs/main").replace(/\\/g, '/')]);

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
	var genConfigProcess = getCommandLineChildProcess("/ida64.exe", ["-Tnintendo", "-Lidalog.txt", "-c", "-S\"" + mcsemaPythonPath + " --output" + game + ".cfg --std-defs " + path.resolve("games/" + game + "/defs.txt").replace(/\\/g, '/') + " --arch aarch64 --os linux --entrypoint nnMain\"", path.resolve("games/" + game + "/exefs/main").replace(/\\/g, '/')]);

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
	var mcsemaProcess = getCommandLineChildProcess(config.mcsema_path + "/bin/mcsema-lift-5.0.exe --platform linux --architecture aarch64 --cfg-path " + game + ".cfg --output-path" + game + ".bc");

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
	if(target === "web") {
		nativeExecutableGenProcess = child_process.spawn("emcc -O3" + game + ".bc -o" + game + ".js");
	} else if(target === "native-64bit" || target === "native-32bit") {
		if(!fs.existsSync(binaryFolder)) {
			fs.mkdirSync(binaryFolder);
		}
		// https://llvm.org/docs/CommandGuide/llc.html
		nativeExecutableGenProcess = child_process.spawn(config.LLVM_path + "/bin/llc -O=3 -obj= -o" + binaryFolder + "/maingamebinary.o --stats " + game + ".bc");
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
		if(target === "native-64bit") {
			console.log("-----START MAKE------");
			makefileProcess = getCommandLineChildProcess("make ARCH=64");
		} else if(target === "native-32bit") {
			console.log("-----START MAKE------");
			makefileProcess = getCommandLineChildProcess("make ARCH=32");
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
	// await startGenSdkFuncs(gameName);
	await startGenConfig(gameName);
	// await startMcsema(gameName);
	// await generateNativeExecutable(gameName, "native-64bit");
}

genGameExecutable("smm2");