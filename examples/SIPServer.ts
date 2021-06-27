import log4js = require("log4js");
// 日志文件系统配置
log4js.configure({
  appenders: {
    out: {type:'stdout'},
    app: {type: 'file', filename: 'application.log'}
  },
  categories: {
    default: {appenders:['out', 'app'], level: 'debug'}
  }
});

const logger = log4js.getLogger();
import log4js_extend = require("log4js-extend");
log4js_extend(log4js, {
  path: __dirname + "/a.log",
  format: "at @name (@file:@line:@column)"
});

// 加载SIP协议栈
import sip = require("../sip");
import digest = require("../digest");
import events = require("events");

// 用于处理XML消息体
import Convert = require("xml-js");

// 记录的会话数组，ID值为call-id,from.tag,to.tag
let dialogs:[];
// 记录所有呼叫信息的数组，ID值为头域的call-id
let call:[];

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
// 上下文
let context = {
  // UAS的域ID
  realm: '3402000000',
  // 认证算法选择
  qop: 'auth-int',
  // 国标中SIP服务器的编码
  server_account: '34020000002000000001',
  _this: new events.EventEmitter(),
  supportMethod: 'REGISTER'||'INVITE'||'ACK'||'CANCEL'||'BYE'||'OPTIONS'||'INFO'||'SUBSCRIBE'||'NOTIFY'||'MESSAGE'
}
let request = {
  // 需要上层确认请求消息类型
  method: 'REGISTER',
  // 请求URI sip:11010200001320000001@192.168.27.95:20002;transport=tcp
  // 实例化后：user:11010200001320000001 password:null host:192.168.27.95 port:20002 params.transort=tcp
  uri: 'sip:34020000002000000011@127.0.0.1:5070;transport=ws',
  // 请求消息头域内容
  headers: {
    // 消息接收者的信息
    to: {
      uri: 'sip:34020000002000000011@127.0.0.1'
    },
    // 请求消息的发送者信息，from.tag用于和call-id、to.tag一起在UA双方建立一个对话Dialog？
    from: {
      uri: 'sip:34020000002000000011@127.0.0.1',
      tag: '11785'
    },
    // 序列号用于标识消息所在的事务
    cseq: {
      method: "REGISTER",
      seq: 1
    },
    // call-id 相同则对应相同的媒体会话，国标中这个值不同事务有不同的不重复的值？
    // 但是BYE消息中的CALL-ID和INVITE请求中的一致
    'call-id': 1111111111,
    // 国标中根据消息类型，参数值的含义也不同，但是都有这行
    contact: [{uri: 'sip:101@somewhere.local', params: {expires: 300}}],
    // 消息体数据长度
    'content-length': 0
  },
  // 消息体数据
  content: undefined
}

// 在册的SIP账号密码信息数组，不在这里定义过的SIP设备的注册请求会被拒绝
var registry = {
  '34020000002000000011' : {password: "Pg0YXL0V"}
};

// debugger;

logger.info('localhost name=%s',context.realm);

// 注册 REGISTER 事件，处理 REGISTER 请求
context._this.on('REGISTER', (rq, remote)=> {
  logger.info('call register');

  let username = sip.parseUri(rq.headers.to.uri).user;

  let userInfo = registry[username];
  logger.info('register username',username);

  if(!userInfo) {
    // 没有登记的用户，这里直接禁止授权
    logger.error('没有登记的用户，这里直接禁止授权:' , username);
    let session = {realm: context.realm};
    if (!rq.headers.to.params.tag || rq.headers.to.params.tag === '')
      rq.headers.to.params.tag = generateTag();
    sip.send(digest.challenge(session, sip.makeResponse(rq, 401, 'Unauthorized')), function (m) {
      if (m) {
        logger.warn(m);
      }
    });
    return;
  }
  else {
    // 这里应该对server_account再校验一下。但有的网上测试IPC程序server_account没用到uri里。这里先简单实现下原理。
    userInfo.session = userInfo.session || {realm: context.realm};
    if (!rq.headers.to.params.tag || rq.headers.to.params.tag === '')
      rq.headers.to.params.tag = generateTag();
    if(!digest.authenticateRequest(userInfo.session, rq, {user: username, password: userInfo.password})) {
      sip.send(digest.challenge(userInfo.session, sip.makeResponse(rq, 401, 'Unauthorized')));
    }
    else {
      // 完成授权
      userInfo.contact = rq.headers.contact;
      var rs = sip.makeResponse(rq, 200, 'Ok');
      rs.headers.contact = rq.headers.contact;
      sip.send(rs);

      // 记录设备信息
      devices[username] = {
        remoteCode: username,
        remoteAddress: remote.address,
        remotePort: remote.port,
        protocol: remote.protocol,
        deviceCode: context.server_account,
        deviceAccount: context.server_account,
        devicePassword: 'Pg0YXL0V',
        localAddress: remote.local.address,
        localPort: remote.local.port,
        heartbeat: 30,
        status: 'OffLine',
        CSeq: 1,
        SN: 1,
        failed: 0
      }
    }
  }
});
// 注册 INVITE 事件，处理 INVITE 请求
context._this.on('INVITE', (rq, remote)=> {
});
// 注册 ACK 事件，处理 ACK 请求
context._this.on('ACK', (rq, remote)=> {
});
// 注册 CANCEL 事件，处理 CANCEL 请求
context._this.on('CANCEL', (rq, remote)=> {
});
// 注册 BYE 事件，处理 BYE 请求
context._this.on('BYE', (rq, remote)=> {
});
// 注册 OPTIONS 事件，处理 OPTIONS 请求
context._this.on('OPTIONS', (rq, remote)=> {
});
// 注册 INFO 事件，处理 INFO 请求
context._this.on('INFO', (rq, remote)=> {
});
// 注册 SUBSCRIBE 事件，处理 SUBSCRIBE 请求
context._this.on('SUBSCRIBE', (rq, remote)=> {
});
// 注册 NOTIFY 事件，处理 NOTIFY 请求
context._this.on('NOTIFY', (rq, remote)=> {
});
// 注册 MESSAGE 事件，处理 MESSAGE 请求
context._this.on('MESSAGE', (rq, remote)=> {
  if (!rq.headers.to.params.tag || rq.headers.to.params.tag === '')
    rq.headers.to.params.tag = generateTag();
  logger.info(rq.method);
  // const js = Convert.xml2js(message.content);
  // logger.info(js.declaration);
  // logger.info(js.elements);
  // for (let el of js.elements) {
  //   if (el.name.toLowerCase() === 'notify') {
  //     for (let i of el.elements) {
  //       if (i.name.toLowerCase() === 'cmdtype') {
  //         if (i.elements[0].text.toString().toLowerCase() === 'keepalive')
  //           sip.send(sip.makeResponse(message, 200, 'ok'));
  //       }
  //     }
  //   }
  // }
  const jsc = Convert.xml2js(rq.content, {compact: true});
  if (jsc['Query'] && jsc['Query']['CmdType'] && jsc['Query']['CmdType']._text === 'RecordInfo') {
    sip.send(sip.makeResponse(rq, 200, 'ok'));
  }
  else if (jsc['Notify'] && jsc['Notify']['CmdType']) {
    let cmdType = jsc['Notify']['CmdType']._text
    if (cmdType.toLowerCase()  === 'keepalive') {
      sip.send(sip.makeResponse(rq, 200, 'ok'));
    }
    else if (cmdType.toLowerCase() === 'alarm') {
      sip.send(sip.makeResponse(rq, 200, 'ok'));
      let username = sip.parseUri(rq.headers.from.uri).user;
      INVITE(devices[username]);
    }
  }
});

sip.start(
  {
    logger: {
      send: function(message, address) {
        logger.info("\n==send==:\n" , sip.stringify(message),address);
      },
      recv: function(message, address) {
        logger.info("\n==recv==:\n" , sip.stringify(message),address);
      },
      trace: function(m, ...a) {
        logger.trace(m, ...a);
      },
      debug: function(m, ...a) {
        logger.debug(m, ...a);
      },
      info: function(m, ...a) {
        logger.info(m, ...a);
      },
      warn: function(m, ...a) {
        logger.warn(m, ...a);
      },
      error: function(m, ...a) {
        logger.error(m, ...a);
      },
      fatal: function(m, ...a) {
        logger.fatal(m, ...a);
      },
      mark: function(m, ...a) {
        logger.mark(m, ...a);
      },
    },
    port: 5060,
    hostname: 'localhost',
    user: context.server_account,
    address: '0.0.0.0',
    ws_port: 5070,
  },
  (rq, remote)=> {
    try {
      if (rq.method != 'REGISTER' && rq.headers.to.params.tag) {

      }
      else {
        switch (rq.method) {
          case 'REGISTER':
          case 'INVITE':
          case 'ACK':
          case 'CANCEL':
          case 'BYE':
          case 'OPTIONS':
          case 'INFO':
          case 'SUBSCRIBE':
          case 'NOTIFY':
          case 'MESSAGE':
            context._this.emit(rq.method, rq, remote);
            break;
          default:
            context._this.emit('UnSupport', rq, remote);
            break;
        }
      }
    }
    catch (e) {
      logger.fatal(e)
    }
  }
)

logger.info('sip.stack start ok');

// 构建命令行式交互
const readline = require('readline')
const chalk = require("chalk");
const figlet = require("figlet");

const init = () => {
  console.log(
    chalk.green(
      figlet.textSync("SIP Server CLI", {
        font: "Henry 3D",
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

// 需要注册的设备信息
let devices:Device[] = [];
type Device = {
  remoteCode, // SIP服务器编码
  remoteAddress, // SIP服务器IP
  remotePort, // SIP服务器端口
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

  let uri = 'sip:'+device.remoteCode+'@'+device.remoteAddress+':'+device.remotePort
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

function INVITE(device: Device) {
  let rq = makeRequest("INVITE", device, {
    headers: {
      from: {
        uri: '',
        params: {
          tag: generateTag()
        }
      },
      'call-id': generateTag(),
      'Content-Type': 'application/sdp',
    },
    content:
      'v=0\r\n'+
      'o=- 13374 13374 IN IP4 172.16.2.2\r\n'+
      's=-\r\n'+
      'c=IN IP4 172.16.2.2\r\n'+
      't=0 0\r\n'+
      'm=audio 16424 RTP/AVP 0 8 101\r\n'+
      'a=rtpmap:0 PCMU/8000\r\n'+
      'a=rtpmap:8 PCMA/8000\r\n'+
      'a=rtpmap:101 telephone-event/8000\r\n'+
      'a=fmtp:101 0-15\r\n'+
      'a=ptime:30\r\n'+
      'a=sendrecv\r\n'
  });
  sip.send(rq, (rs, remote)=> {
    try {
      if (rs.status != 200) {
        console.info("recv non 200 ok response from server for alarm message.");
      }
      else {
        console.log("alarm ok");
      }
    }
    catch (e) {
      console.log(e);
      console.log(e.stack);
    }
  })
}
