// 构建命令行式交互
const readline = require('readline')
const chalk = require("chalk");
const figlet = require("figlet");
const os = require('os');
const net = require('net')

const init = () => {
  console.log(
    chalk.green(
      figlet.textSync("SIP Client CLI", {
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

// SIP Stack
let sip = require('../sip');
let digest = require('../digest');
let util = require('util');

os.networkInterfaces()

/**
 * 1. 注册流程，每隔1小时发起注册请求，或者3次没有收到心跳响应就需要变更状态为重新注册
 * 2. 间隔指定时间要发送一次心跳请求，3次没有收到就需要变更注册状态
 * 3. 准备告警函数可以发送告警信息
 * 4. 准备下线函数，可以随时让设备下线
 * 5.
 */
let demo = {
  method: undefined,
  uri: undefined,//'sip:34020000002000000011@192.168.123.111:5060;transport=TCP',
  headers: {
    via: undefined,
    to: {
      uri: undefined,//'sip:34020000002000000011@127.0.0.1',
      tag: undefined,
    },
    from: {
      uri: undefined,//'sip:34020000002000000011@127.0.0.1',
      tag: undefined,
    },
    cseq: {
      method: undefined,//"REGISTER",
      seq: undefined
    },
    'call-id': undefined,
    contact: undefined,//[{uri: 'sip:101@somewhere.local', params: {expires: 300}}],
    'content-length': 0
  },
  content: undefined
}

// 建立的对话数组
let dialogs = {};
// 需要注册的设备信息
let devices:Device[] = [];
type Device = {
  serverCode, // SIP服务器编码
  serverAddress, // SIP服务器IP
  serverPort, // SIP服务器端口
  protocol, // 通信协议

  deviceCode, // 设备编码
  deviceAccount, // 设备认证账号
  devicePassword // 设备认证密码
  localAddress, // 本机IP地址
  // runtime variable
  CSeq,
  status,
  callId,
}
type Status = 'OffLine'|'OnRegister'|'OnLine'
type MethodType = 'REGISTER'|'INVITE'|'ACK'|'CANCEL'|'BYE'|'OPTIONS'|'INFO'|'SUBSCRIBE'|'NOTIFY'|'MESSAGE'

function rstring() { return Math.floor(Math.random()*1e6).toString(); }

sip.start({
    logger: {
      send: (msg)=> {
        console.log("==============send=================")
        console.log(sip.stringify(msg))
      },
      recv: (msg)=> {
        console.log("==============recv=================")
        console.log(sip.stringify(msg))
      }
    },
    port: 25060, ws_port: 25070
  },
  (msg, remote, stream) => {
    if(msg.headers.to.params.tag) { // check if it's an in dialog request
      const id = [msg.headers['call-id'], msg.headers.to.params.tag, msg.headers.from.params.tag].join(':');

      if(dialogs[id])
        dialogs[id](msg, remote);
      else
        sip.send(sip.makeResponse(msg, 481, "Call doesn't exists"));
    }
    else
      sip.send(sip.makeResponse(msg, 405, 'Method not allowed'));
  }
)

/**
 * 创建SIP请求消息
 * @param method 请求方法
 * @param device 设备信息
 * @param extension 扩展字段
 */
function makeRequest(method: MethodType, device: Device, extension: any) {
  if (!method || !device) return;
  let rq = demo;
  let uri = 'sip:'+device.serverCode+'@'+device.serverAddress+':'+device.serverPort
  let toUri = uri;
  let fromUri = 'sip:'+device.deviceCode+'@'+device.localAddress

  switch (method) {
    case "REGISTER":
      toUri = fromUri;  // 注册消息时候，from和to字段值一样
      break;
    case "INVITE":
    case "ACK":
    case "BYE":
    case "CANCEL":
    case "INFO":
    case "MESSAGE":
    case "NOTIFY":
    case "OPTIONS":
    case "SUBSCRIBE":
    default:
      console.log('UnSupport method: ' + method);
      return
  }
  rq.headers.cseq.method = rq.method = method;
  rq.uri = uri;
  rq.headers.from.uri = fromUri;
  rq.headers.to.uri = toUri;

  rq.headers['call-id'] = '123456'
  rq.headers.contact = [{uri: 'sip:101@somewhere.local', params: {expires: 300}}]
  if(extension) {
    if(extension.headers) Object.keys(extension.headers).forEach(function(h) {
      // Object.keys(extension.headers[h]).forEach((s)=>{
      //   rq.headers[h][s] = extension.headers[h][s];
      // })
      rq.headers[h] = extension.headers[h];
    });
    rq.content = extension.content;
    if (rq.content)
      rq.headers["content-length"] = rq.content.length;
  }
  // if (extension.headers && extension.headers.cseq && extension.headers.cseq.seq)
  //   rq.headers.cseq.seq = extension.headers.cseq.seq
  if (!rq.headers.cseq.seq)
    rq.headers.cseq.seq = device.CSeq++;

  let transport = device.protocol.toLowerCase() === 'tcp' ? ';transport=tcp' : ';transport=udp'
  rq.uri = rq.uri + transport

  return rq;
}
devices['34020000002000000011'] = {
  serverCode: '34020000002000000001',
  serverAddress: '192.168.123.138',
  serverPort: 5060,
  protocol: 'tcp',
  deviceCode: '34020000002000000011',
  deviceAccount:'34020000002000000011',
  devicePassword: 'Pg0YXL0V',
  localAddress: '192.168.123.111',
  status: 'OffLine',
  CSeq: 1
}
// let msg = makeRequest("REGISTER", devices['34020000002000000011'], {
//   headers: {
//     cseq: {seq: 30},
//     from: {
//       uri: "sip:12345@192.168.123.1",
//       tag: '123123123123',
//     },
//   },
//   content: '<?xml version="1.0" encoding="GB2312"?>\r\n' +
//     '<Notify>\r\n' +
//     '<CmdType>Keepalive</CmdType>\r\n' +
//     '<SN>49</SN>\r\n' +
//     '<DeviceID>34020000002000000011</DeviceID>\r\n' +
//     '<Status>OK</Status>\r\n' +
//     '</Notify>\r\n'
// })
// console.log(msg);
// console.log(sip.stringify(msg))
register(devices['34020000002000000011'])
/**
 * 注册设备
 * @param device
 */
function register(device: Device) {
  let rq = makeRequest("REGISTER", device, {
    headers: {
    }});
  sip.send(rq, (rs, remote)=> {
    try {
      if (rs.status === 401 || rs.status === 407) {
        // @ts-ignore
        rq.headers.via.pop();
        rq.headers.cseq.seq++;
        let context = {}
        digest.signRequest(context, rq, rs, {user: device.deviceCode, password: device.devicePassword});
        sip.send(rq, (rs1, remote1)=>{
          // @ts-ignore
          if (200 <= rs1.status < 300) {
            if (false === digest.authenticateResponse(context, rs))
              console.log('failed to authenticate server');
            else
              console.log('REGISTER ok');
          }
        });
      }
      else { // @ts-ignore
        if (300 > rs.status >= 200) {
          console.log("Ok");
        }
        else {
          console.log('failed to register\r\n' + rs);
        }
      }
    }
    catch (e) {
      console.log(e);
      console.log(e.stack);
    }
  })
}

/**
 * 定时心跳上报及处理函数
 * @param device
 */
async function keepalive(device: Device) {

}

/**
 * 告警上报处理函数
 * @param device
 */
function notify(device: Device) {

}
