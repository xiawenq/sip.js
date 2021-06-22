import log4js = require("log4js");
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
import sip = require("../sip");
import digest = require("../digest");
import Convert = require("xml-js");




var server_account = '34020000002000000001';
var registry = {
  '34020000002000000011' : {password: "Pg0YXL0V"}
};

debugger;

var realm = '3402000000';

logger.info('localhost name=%s',realm);
sip.start(
  {
    logger: {
      send: function(message, address) {
        logger.info("==send==:" , message,address);
      },
      recv: function(message, address) {
        // logger.info("==recv==:" , message,address);
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
    ws_port: 5070,
  },
  function(message) {
    try {
      logger.info('----------------------',message);
      if(message.method.toUpperCase() == 'REGISTER') {
        logger.info('call register');

        var username = sip.parseUri(message.headers.to.uri).user;

        logger.info('register username',username);
        var userinfo = registry[username];
        //logger.info('userinfo', userinfo);

        if(!userinfo) {
          // 没有登记的用户，这里直接禁止授权
          logger.error('没有登记的用户，这里直接禁止授权:' , username);
          var session = {realm: realm};
          sip.send(digest.challenge(session, sip.makeResponse(message, 401, 'Unauthorized')), function (m) {
            if (m) {
              logger.warn(m);
            }
          });
          return;
        }
        else {
          // 这里应该对server_account再校验一下。但有的网上测试IPC程序server_account没用到uri里。这里先简单实现下原理。
          userinfo.session = userinfo.session || {realm: realm};
          if(!digest.authenticateRequest(userinfo.session, message, {user: username, password: userinfo.password})) {
            sip.send(digest.challenge(userinfo.session, sip.makeResponse(message, 401, 'Unauthorized')));
          }
          else {
            // 完成授权
            userinfo.contact = message.headers.contact;
            var rs = sip.makeResponse(message, 200, 'Ok');
            rs.headers.contact = message.headers.contact;
            sip.send(rs);
          }
        }
      }
      else if (message.method.toUpperCase() == 'MESSAGE') {
        logger.info(message.method);
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
        const jsc = Convert.xml2js(message.content, {compact: true});
        if (jsc['Query'] && jsc['Query']['CmdType'] && jsc['Query']['CmdType']._text === 'RecordInfo') {
          sip.send(sip.makeResponse(message, 200, 'ok'));
        }
        else if (jsc['Notify'] && jsc['Notify']['CmdType'] && jsc['Notify']['CmdType']._text === 'Keepalive') {
          sip.send(sip.makeResponse(message, 200, 'ok'));
        }
      }

    } catch(e) {
      logger.error(e);
      sip.send(sip.makeResponse(message, 500, "Server Internal Error"));
    }
  });

