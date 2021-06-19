declare module 'sip' {
  // an object optionally containing following properties.
  export type Options = {
    // port to be used by UDP and TCP transports. 5060 by default.
    port?: number;
    // interface address to be listen on. By default sip.js listens on all interfaces.
    address?: string;
    // enables UDP transport. Enabled by default.
    udp?: boolean;
    // enables TCP transport. Enabled by default.
    tcp?: boolean;
    /*
    options object for tls transport. It will be passed as options parameter to `tls.createServer` and
    `tls.connect` node.js APIs. See [description in node.js API documentation](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
    If `tls' is ommited TLS transport will be disabled.
     */
    tls?: any;
    // port for TLS transport to listen on. 5061 by default.
    tls_port?: number;
    /*
    address and hostname to be used within sip.js generated local uris and via headers. Sip.js will use `options.publicAddress` when
    it's defined, then fallback to `options.hostname` and the fallback to value returned by node.js `os.hostname()` API.
     */
    publishAddress?: string; hostname?: string;
    // port for WebSockets transport. To enable WebSockets transport, this field is required; no default provided.
    ws_port?: number;
    // (For TCP and TLS ) Max allowed length in bytes of a SIP message headers ( without content ). ; default: 60480.
    maxBytesHeaders?: number;
    // (For TCP and TLS ) Max allowed content length for a SIP message. ; default: 604800.
    maxContentLength?: number;
    // for log print
    logger?: {
      /**
       * 记录发送的消息
       * @param message 发送的sip消息
       * @param address 发往的地址
       */
      send:(message: any, address: any)=>void;
      /**
       * 记录接收的消息
       * @param message 接收的sip消息
       * @param address 接收的地址
       */
      recv:(message: any, address: any)=>void;

      trace?:(message: any, ...args: any[])=>void;

      debug?:(message: any, ...args: any[])=>void;

      info?:(message: any, ...args: any[])=>void;

      warn?:(message: any, ...args: any[])=>void;

      error?:(message: any, ...args: any[])=>void;

      fatal?:(message: any, ...args: any[])=>void;

      mark?:(message: any, ...args: any[])=>void;
    };
  }
  export function start(options:Options, onRequest?:(message:any, remote?:any)=>void):void;

  /**
   * 解析URI
   * @param s
   */
  export function parseUri(s:any):any;
  export function send(m: any, callback?:(m:any)=>void):void;

  /**
   * 创建一个响应
   * @param rq
   * @param status
   * @param reason
   * @param extension
   */
  export function makeResponse(rq: any, status: any, reason: any, extension?: any): any;
}
declare module 'sip/digest' {
  export function challenge(ctx: any, rs: any): any;
  export function authenticateRequest(ctx: any, rq: any, creds: any):any;
}
