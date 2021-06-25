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
    if(!digest.authenticateRequest(userInfo.session, rq, {user: username, password: userInfo.password})) {
      sip.send(digest.challenge(userInfo.session, sip.makeResponse(rq, 401, 'Unauthorized')));
    }
    else {
      // 完成授权
      userInfo.contact = rq.headers.contact;
      var rs = sip.makeResponse(rq, 200, 'Ok');
      rs.headers.contact = rq.headers.contact;
      sip.send(rs);
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
  else if (jsc['Notify'] && jsc['Notify']['CmdType'] && jsc['Notify']['CmdType']._text === 'Keepalive') {
    sip.send(sip.makeResponse(rq, 200, 'ok'));

    // var requestMsg = {
    //   uri: rq.headers.from.uri,
    //   method: 'OPTIONS',
    //   version: "2.0",
    //   headers: {
    //     //   via: [{version: "2.0", protocol: 'TCP', host: 'localhost', port: 5060, params: {branch:'12345'}}],
    //     //   'content-length': 0,
    //   },
    //   // content: ''
    // };
    // logger.info(requestMsg);
    // sip.send(requestMsg, (rsp)=> {
    //   logger.info(sip.stringify(rsp));
    // })
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
