'use strict';

const util = require('silence-js-util');
const R1 = /^[0-9a-v]+$/i;
const R2 = /^[0-9a-z]+$/i;
const Long = require('long');

class TokenSessionStore {
  constructor(config) {
    this.SessionUserFreeList = new util.FreeList(config.UserClass, config.freeListSize);
    this.logger = config.logger;
    this.tokenMode = config.tokenMode || 'cookie';
    this.sessionKey = config.sessionKey || 'SILENCE_SESSION';
    this.passwordService = config.passwordService;
    this._headers = {
      'Content-Type': 'application/json;charset=utf-8',
      [this.sessionKey]: ''
    };
  }
  init() {
    return this.passwordService.init();
  }
  close() {
    return this.passwordService.close();
  }
  /**
   * getRespHeaders will be called after each request been handled
   */
  getRespHeaders(ctx) {
    if (!ctx._user || !ctx._user.isLogin) {
      return null;
    }
    let NOW = this.passwordService.now;
    let ts = this.passwordService.calcTS(NOW);
    if (ts === ctx._user.sessionId) {
      return null;
    }
    let pass = this.passwordService.getByTS(ts);
    if (!pass) {
      throw new Error('login:passwordService getByTS return null');
    }
    let ts_str = ts.toString(32).toUpperCase();
    let ts_len_str = ts_str.length.toString(32);
    
    let uid_str = Long.fromString(uid, 10).toString(36);
    let uid_len_str = (31 - uid_str.length).toString(32).toUpperCase();
    
    const hmac = crypto.createHmac('sha512', pass);
    hamc.update(uid_str + ts_str);
    hash = hamc.digest('base64');
    let token = uid_len_str + ts_len_str + ts_str + uid_str + hash;

    if (this.tokenMode === 'cookie') {
      ctx.cookie.set(this.sessionKey, token, {
        expires: new Date('3000-04-02')
      });
      return null;
    } else {
      this._headers[this.sessionKey] = token;;
      return this._headers;
    }
  }
  createUser() {
    return this.SessionUserFreeList.alloc();
  }
  freeUser(user) {
    this.SessionUserFreeList.free(user);
  }
  touch(ctx) {
    return new Promise((resolve, reject) => {
      let token = this.tokenMode === 'cookie' ? ctx.cookie.get(this.sessionKey) : ctx.headers[this.sessionKey];
      if (!token) {
        return resolve(0);
      }

      let tmp_str = token[0];
      if (!tmp_str || !R1.test(tmp_str)) {
         return resolve(1);
      }
      let uid = 31 - parseInt(tmp_str, 32);
      // console.log(uid);
      tmp_str = token[1];
      if (!tmp_str || !R1.test(tmp_str)) {
        return resolve(1);
      }
      let ts = parseInt(tmp_str, 32);
      // console.log(ts)
      let ts_str = token.substring(2, 2 + ts);
      // console.log(ts_str)
      if (!ts_str || !R1.test(ts_str)) {
        return resolve(1);
      }
      let i = 2 + ts;
      ts = parseInt(ts_str, 32);
      // console.log(ts);
      let pass = this.passwordService.getByTS(ts);
      if (!pass) {
        return resolve(1);
      }

      // console.log(pass);
      
      let uid_str = token.substring(i, i + uid);
      // console.log(uid_str);
      if (!uid_str || !R2.test(uid_str)) {
        return resolve(1);
      }
      i += uid;
      uid = Long.fromString(uid_str, 36);
      
      let hash = token.substring(i);
      if (!hash) {
        return resolve(1);
      }
      // console.log(hash);

      const hmac = crypto.createHmac('sha512', pass);
      hamc.update(uid_str + ts_str);
      const dst_hash = hamc.digest('base64');
      // console.log(dst_hash);
      if (dst_hash !== hash) {
        return resolve(1);
      }
      if (ctx._user === null) {
        ctx._user = this.createUser();
      }
      ctx._user.sessionId = ts;
      ctx._user._uid = uid.toString();
      // data && ctx._user.assign(data);
      ctx._user.isLogin = true;
      resolve(0);
    });
  }
  login(ctx, remember) {
    return new Promise((resolve, reject) => {
      ctx._user.isLogin = true;
      resolve(true);
    });
  }
  logout(ctx) {
    return new Promise((resolve, reject) => {
      if (this.tokenMode === 'cookie') {
        ctx._user && ctx.cookie.set(this.sessionKey, '');
      }
      resolve(true);
    });
  }
}

module.exports = TokenSessionStore;