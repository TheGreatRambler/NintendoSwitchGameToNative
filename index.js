const config        = require("./config.json");
const fs            = require("fs");
const child_process = require("child_process");
const path          = require("path");

// TODO convert this crap to makefile

var res = function(thePath) {
	return path.resolve(thePath).replace(/\\/g, '/');
};
var idaLogPath  = res("idatemplog.txt");
var tailCommand = "tail";

var idaCommandPrefix = `${config.IDA_path}/idat64.exe -A -Tnintendo -L${idaLogPath}`;

// Executable format: AARCH64 v8A 64 little	default
// AARCH64:LE:64:v8A (1.4)
// Generic ARM v8.3-A Little endian instructions, Little endian data
// Use SwIPC for the rest of the extern functions
async function startGenSdkFuncs(game) {
	await new Promise(resolve => {
		console.log("------START GENERATING SDK FUNCS------");
		// Make sure log file exists, IDA chokes if it isn't present
		// This will create the file empty
		fs.closeSync(fs.openSync(idaLogPath, "w"));
		// Run command
		var cmd = `${idaCommandPrefix} -S\"${res("dumpsdkfuncs.py")} ${res("games/" + game + "/defs.txt")} ${res("games/" + game + "/defs.h")} ${res("bin/demumble.exe")}\" ${res("games/" + game + "/exefs/main")}`;
		console.log(cmd);
		var getSdkFuncsProcess = child_process.spawn(cmd, {
			shell: true,
			stdio: ["pipe", "pipe", "pipe"],
		});

		var logOutput = child_process.spawn(tailCommand, ["-f", idaLogPath]);

		logOutput.stdout.on("data", function(data) {
			process.stdout.write(data.toString());
		});

		logOutput.stderr.on("data", function(data) {
			process.stderr.write(data.toString());
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
		var mcsemaPythonPath = res("mcsema/lib/ida7/get_cfg.py");
		// Clear again
		fs.closeSync(fs.openSync(idaLogPath, "w"));
		var cmd = `${idaCommandPrefix} -S\"${mcsemaPythonPath} --output ${res("games/" + game + "/config.cfg")} --std-defs ${res("games/" + game + "/defs.txt")} --arch aarch64 --os linux --entrypoint nnMain\" ${res("games/" + game + "/exefs/main")}`;
		console.log(cmd);
		var genConfigProcess = child_process.spawn(cmd, {
			shell: true,
			stdio: ["pipe", "pipe", "pipe"],
		});

		var logOutput = child_process.spawn(tailCommand, ["-f", idaLogPath]);

		logOutput.stdout.on("data", function(data) {
			process.stdout.write(data.toString());
		});

		logOutput.stderr.on("data", function(data) {
			process.stderr.write(data.toString());
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
		console.log("------START LIFT------");
		// First load the image
		var loadCommand = "docker load -i mcsema.tar";
		console.log(loadCommand);
		var imageImportProcess = child_process.spawn(loadCommand, {
			shell: true,
			stdio: ["pipe", "pipe", "pipe"],
		});

		imageImportProcess.stdout.on("data", data => {
			console.log(data.toString());
		});

		imageImportProcess.stderr.on("data", function(data) {
			process.stderr.write(data.toString());
		});

		imageImportProcess.on("error", (error) => {
			console.error(error.message);
		});

		imageImportProcess.on("close", code => {
			var cmd;
			if(process.env.MSYSTEM) {
				// MSYS version (does name mangling)
				cmd = `docker run -v ${"/" + __dirname.replace(":", "").replace(/\\/g, "/")}:/build --workdir=/build --name mcsema_bc_build docker.pkg.github.com/lifting-bits/mcsema/mcsema-llvm1000-ubuntu20.04-amd64:latest mcsema-lift-10.0 --os linux --arch aarch64 --cfg ${"games/" + game + "/config.cfg"} --output ${"games/" + game + "/bitcode.bc"}`
			} else {
				// CMD version
				cmd = `docker run -v ${__dirname}:/build --workdir=/build --name mcsema_bc_build docker.pkg.github.com/lifting-bits/mcsema/mcsema-llvm1000-ubuntu20.04-amd64:latest mcsema-lift-10.0 --os linux --arch aarch64 --cfg ${"games/" + game + "/config.cfg"} --output ${"games/" + game + "/bitcode.bc"}`
			}

			console.log(cmd);
			var mcsemaProcess = child_process.spawn(cmd, {
				shell: true,
				stdio: ["pipe", "pipe", "pipe"],
			});

			mcsemaProcess.stdout.on("data", data => {
				console.log(data.toString());
			});

			mcsemaProcess.stderr.on("data", function(data) {
				process.stderr.write(data.toString());
			});

			mcsemaProcess.on('error', (error) => {
				console.error(error.message);
			});

			mcsemaProcess.on("close", code => {
				var imageDeleteCmd = "docker rm mcsema_bc_build";
				console.log(imageDeleteCmd);
				var containerCloseProcess = child_process.spawn(imageDeleteCmd, {
					shell: true,
				});

				containerCloseProcess.stdout.on("data", data => {
					console.log(data.toString());
				});

				containerCloseProcess.stderr.on("data", function(data) {
					process.stderr.write(data.toString());
				});

				containerCloseProcess.on('error', (error) => {
					console.error(error.message);
				});

				containerCloseProcess.on("close", code => {
					console.log("------DONE LIFT------");
					resolve();
				});
			});
		});
	});
}

async function generateNativeExecutable(game, target) {
	await new Promise(resolve => {
		console.log("------START BUILDING NATIVE EXECUTABLE------");
		var nativeExecutableGenProcess;
		const binaryFolder = "./bin";
		if(target === "web") {
			nativeExecutableGenProcess = child_process.spawn(`emcc -O3 ${res(game + ".bc")} -o ${res(game + ".js")}`, {
				shell: true,
				stdio: ["pipe", "pipe", "pipe"],
			});
		} else if(target === "native-64bit" || target === "native-32bit") {
			if(!fs.existsSync(binaryFolder)) {
				fs.mkdirSync(binaryFolder);
			}
			// https://llvm.org/docs/CommandGuide/llc.html
			nativeExecutableGenProcess = child_process.spawn(`${config.LLVM_path} /bin/llc -O=3 -o ${res(binaryFolder + "/maingamebinary.o")} --stats ${res(game + ".bc")}`, {
				shell: true,
				stdio: ["pipe", "pipe", "pipe"],
			});
		}

		nativeExecutableGenProcess.stdout.on("data", data => {
			console.log(data.toString());
		});

		nativeExecutableGenProcess.stderr.on("data", data => {
			console.error(data.toString());
		});

		nativeExecutableGenProcess.on('error', (error) => {
			console.error(error.message);
		});

		nativeExecutableGenProcess.on("close", code => {
			console.log("-----DONE START BUILDING NATIVE EXECUTABLE------");
			var makefileProcess;
			if(target === "native-64bit") {
				console.log("-----START MAKE------");
				makefileProcess = child_process.spawn(`make ARCH=64`, {
					shell: true,
					stdio: ["pipe", "pipe", "pipe"],
				});
			} else if(target === "native-32bit") {
				console.log("-----START MAKE------");
				makefileProcess = child_process.spawn(`make ARCH=32`, {
					shell: true,
					stdio: ["pipe", "pipe", "pipe"],
				});
			}

			makefileProcess.stdout.on("data", data => {
				console.log(data.toString());
			});

			makefileProcess.stderr.on("data", data => {
				console.error(data.toString());
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
	await startMcsema(gameName);
	// await generateNativeExecutable(gameName, "native-64bit");
}

genGameExecutable("smm2");