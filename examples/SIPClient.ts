// 构建命令行式交互
const readline = require('readline')
const chalk = require("chalk");
const figlet = require("figlet");

const init = () => {
  console.log(
    chalk.green(
      figlet.textSync("Node JS CLI", {
        font: "Ghost",
        horizontalLayout: "default",
        verticalLayout: "default"
      })
    )
  );
};

const helpMessage = "help 输出帮助\n" +
  "conn\n" +
  "close\n" +
  "notify\n" +
  "";
init();

function readSyncByRl(tips) {
  tips = tips || '> ';

  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(tips, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}
async function main() {
  console.log(helpMessage)
  while(1) {
    let con = true;
    await readSyncByRl('').then((res) => {
      if (res === 'exit') {
        con = false;
      }
      else if (res === 'help')
        console.log(helpMessage)
    });
    if (!con) {
      console.log("exit ok");
      break;
    }
  }
}
main().then(r => {});
