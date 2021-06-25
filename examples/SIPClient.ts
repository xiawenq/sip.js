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
let Convert = require('xml-js')

os.networkInterfaces()

/**
 * 1. 注册流程，每隔1小时发起注册请求，或者3次没有收到心跳响应就需要变更状态为重新注册
 * 2. 间隔指定时间要发送一次心跳请求，3次没有收到就需要变更注册状态
 * 3. 准备告警函数可以发送告警信息
 * 4. 准备下线函数，可以随时让设备下线
 * 5.
 */

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
  localPort,
  heartbeat,
  // runtime variable
  CSeq,
  SN,
  status,
  failed
}
type Status = 'OffLine'|'OnRegister'|'OnLine'
type MethodType = 'REGISTER'|'INVITE'|'ACK'|'CANCEL'|'BYE'|'OPTIONS'|'INFO'|'SUBSCRIBE'|'NOTIFY'|'MESSAGE'

function rstring() { return Math.floor(Math.random()*1e6).toString(); }

/**
 * 根据请求创建对话ID，用于标识一组对话
 * @param sipMsg SIP消息对象
 * @param toTag to.tag值
 */
function makeDialogId(sipMsg, toTag) {
  toTag = sipMsg.headers.to.params.tag || toTag;
  [sipMsg.headers['call-id'], sipMsg.headers.from.params.tag, toTag].join();
}

/**
 * 随机生成tag值
 * @returns {string}
 */
function generateTag() {
  return [(Math.random()+1).toString(36).substring(2)].join('');
}

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
  let rq = {
    method: undefined,
    uri: undefined,//'sip:34020000002000000011@192.168.123.111:5060;transport=TCP',
    headers: {
      via: undefined,
      to: {
        uri: undefined,//'sip:34020000002000000011@127.0.0.1',
        params: {
          tag: undefined,
        }
      },
      from: {
        uri: undefined,//'sip:34020000002000000011@127.0.0.1',
        params: {
          tag: undefined,
        }
      },
      'call-id': undefined,
      cseq: {
        method: undefined,//"REGISTER",
        seq: undefined
      },
      contact: undefined,//[{uri: 'sip:101@somewhere.local', params: {expires: 300}}],
      'content-length': 0
    },
    content: undefined
  }

  if(extension) {
    if(extension.headers) Object.keys(extension.headers).forEach(function(h) {
      rq.headers[h] = extension.headers[h];
    });
    rq.content = extension.content;
    if (rq.content)
      rq.headers["content-length"] = rq.content.length;
  }

  let uri = 'sip:'+device.serverCode+'@'+device.serverAddress+':'+device.serverPort
  let toUri = uri;
  let fromUri = 'sip:'+device.deviceCode+'@'+device.localAddress+':'+device.localPort;
  let transport = device.protocol.toLowerCase() === 'tcp' ? ';transport=tcp' : ';transport=udp'

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
      break;
    default:
      console.log('UnSupport method: ' + method);
      return
  }
  if (!rq.headers.cseq.method) rq.headers.cseq.method = method;
  if (!rq.headers.cseq.seq) rq.headers.cseq.seq = device.CSeq++;
  if (!rq.method) rq.method = method;
  if (!rq.uri) rq.uri = uri;
  if (!rq.headers.from.uri) rq.headers.from.uri = fromUri;
  if (!rq.headers.to.uri) rq.headers.to.uri = toUri;

  if (!rq.headers['call-id']) rq.headers['call-id'] = generateTag();
  if (!rq.headers.contact) rq.headers.contact = [{uri: 'sip:101@somewhere.local', params: {expires: 300}}]

  rq.uri = rq.uri + transport

  return rq;
}
devices['34020000002000000011'] = {
  serverCode: '34020000002000000001',
  serverAddress: '192.168.123.138',
  serverPort: 5060,
  protocol: 'udp',
  deviceCode: '34020000002000000011',
  deviceAccount:'34020000002000000011',
  devicePassword: 'Pg0YXL0V',
  localAddress: '192.168.123.138',
  localPort: 0,
  heartbeat: 30,
  status: 'OffLine',
  CSeq: 1,
  SN: 1,
  failed: 0
}

register(devices['34020000002000000011'])
/**
 * 注册设备
 * @param device
 * @param retryMsg
 */
function register(device: Device, retryMsg?) {
  let rq = retryMsg ? retryMsg : makeRequest("REGISTER", device, {
    headers: {
      from: {
        uri: '',
        params: {
          tag: generateTag()
        },
      },
      'call-id': generateTag()
    }});
  // 第一次发送注册包
  sip.send(rq, (rs, remote)=> {
    try {
      // @ts-ignore
      rq.headers.via.pop();
      if (rs.status === 401 || rs.status === 407) {
        rq.headers.cseq.seq++;
        device.CSeq++;
        if (device.localPort !== sip.parseUri(rq.headers.from.uri).port)
          device.localPort = sip.parseUri(rq.headers.from.uri).port
        let context = {}
        // 算法认证后第二次发送注册包
        digest.signRequest(context, rq, rs, {user: device.deviceCode, password: device.devicePassword});
        sip.send(rq, (rs1, remote1)=>{
          // @ts-ignore
          if (200 <= rs1.status < 300) {
            if (false === digest.authenticateResponse(context, rs))
              console.log('failed to authenticate server');
            else {
              console.log('REGISTER ok');
              keepalive(device);
            }
          }
        });
      }
      else {
        // @ts-ignore
        if (300 > rs.status >= 200) {
          console.log("Ok");
        }
        else {
          console.log('failed to register\r\n' + rs);
          setTimeout(()=>{
            register(device, rq)
          }, 5*1000);
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
 * 异步调用函数,注意：要求第一个参数回调函数
 * @static
 * @param {function} paramFunc 要调用的函数
 * @param {...args} args 要调用的参数
 * @return {...args} 返回回调函数的传入参数列表
 */
async function WaitFunction(paramFunc, ...args) {
  return new Promise((resolve) => {
    paramFunc((...result) => {
      resolve(result);
    }, ...args);
  });
}

/**
 * 定时心跳上报及处理函数
 * @param device
 */
async function keepalive(device: Device) {
  let body = {
    _declaration: {
      _attributes: {
        version: '1.0'
      }
    },
    Notify: {
      CmdType: 'Keepalive',
      SN: device.SN++,
      DeviceID: device.deviceCode,
      Status: 'OK'
    }
  }
  let stringB = Convert.js2xml(body, {compact: true});
  console.log('content: ' + stringB)
  let rq = makeRequest("MESSAGE", device, {
    headers: {
      from: {
        uri: '',
        params: {
          tag: generateTag()
        }
      },
      'call-id': generateTag(),
      'Content-Type': 'Application/MANSCDP+xml'
    },
    content: stringB
  });
  // 第一次发送注册包
  sip.send(rq, (rs, remote)=> {
    try {
      if (rs.status != 200) {
        console.info("recv non 200 ok response from server for keepalive message.");
        device.failed++;
      }
      else {
        console.log("keepalive ok");
      }
      if (device.failed >= 3) {
        console.warn("device offline!!!!");
        device.status = 'Offline';
        device.failed = 0;
        register(device);
        return;
      }
      setTimeout(()=>{
        keepalive(device)
      }, device.heartbeat*1000);
    }
    catch (e) {
      console.log(e);
      console.log(e.stack);
    }
  })
}

/**
 * 告警上报处理函数
 * @param device
 */
function notify(device: Device) {

}
