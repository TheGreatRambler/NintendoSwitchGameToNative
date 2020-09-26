const config = require("./config.json");
const fs = require("fs");
const child_process = require("child_process");

// TODO convert this crap to makefile

var gameName = "smm2";

// Executable format: AARCH64 v8A 64 little	default
// AARCH64:LE:64:v8A (1.4)
// Generic ARM v8.3-A Little endian instructions, Little endian data
// Use SwIPC for the rest of the extern functions
async function startGenConfig(game) {
	console.log("------START GENERATING CONFIG------");
	var genConfigProcess = child_process.spawn(config.IDA_path + "/ida64.exe", ["-S", "'" + config.mcsema_path + "/Lib/site-packages/mcsema_disass-2.0-py3.8.egg/mcsema_disass/ida7/get_cfg.py", "--output", game + ".cfg", "--std-defs", "games/" + game + "/defs.txt", "--arch", "aarch64", "--os", "linux", "--entrypoint", "nnMain'", "games/" + game + "/exefs/main"]);

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
	var mcsemaProcess = child_process.spawn(config.mcsema_path + "/bin/mcsema-lift-5.0.exe", ["--platform", "linux", "--architecture", "aarch64", "--cfg-path", game + ".cfg", "--output-path", game + ".bc"]);

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
		nativeExecutableGenProcess = child_process.spawn("emcc", ["-O3", game + ".bc", "-o", game + ".js"]);
	} else if (target === "native-64bit" || target === "native-32bit") {
		if (!fs.existsSync(binaryFolder)){
			fs.mkdirSync(binaryFolder);
		}
		// https://llvm.org/docs/CommandGuide/llc.html
		nativeExecutableGenProcess = child_process.spawn(config.LLVM_path + "/bin/llc", ["-O=3", "-obj=", "-o", binaryFolder + "/maingamebinary.o", "--stats", game + ".bc"]);
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
			makefileProcess = child_process.spawn("make", ["ARCH=64"]);
		} else if(target === "native-32bit") {
			console.log("-----START MAKE------");
			makefileProcess = child_process.spawn("make", ["ARCH=32"]);
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
	await startGenConfig(gameName);
	await startMcsema(gameName);
	await generateNativeExecutable(gameName, "native-64bit");
}