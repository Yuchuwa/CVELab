var querystring = require('querystring');

var url = null,
  arg = [], 
  nowaData = null;

function defaultMethod(arg, url) {
  // 解析之后的url参数
  if(url[0]){
    if(url[0].indexOf('/') === 0) url[0].replace('/', '');
    arg[2] = url[0].split('/');
  } else {
    arg[2] = null;
  }
  // 继续解析带问号的部分,并使用一个对象返回
  if(url[1] && url[1].length) {
    var param = url[1].split('&');
    var paramObj = {};
    var parse = [];
    for(var i = 0; i < param.length; i ++) {
      parse = param[i].split('=');
      paramObj[parse[0]] = parse[1];
    }
  }
  arg[3] = paramObj;
  return arg;
}

function dealArg(app, url, method, data) {

  for(var key in app.get) {
    if(url.indexOf(key) !== -1) {
      url = url.replace(key, '').split('?');
      arg = defaultMethod(arg, url);
      if(data) arg[4] = data;
      
      if(!(app[method] && app[method][key])) {
        // 报错
        arg[0]('error');
        return;
      }
      app[method][key].apply(this, arg);
      return;
    }
  }
  // 尝试获取静态文件
  arg[0]();
}

function response(app, request, send) {
  url = request.url;
  // 每个方法中的第一个参数为返回数据的调用函数，第二个为需要返回的数据信息
  arg = [send, {status: 404, data: 'api not found'}];
  nowaData = '';

  function dealTask(method) {
    request.addListener('data', function(chunk) {
      nowaData += chunk;
    });
    request.addListener('end', function () {
      dealArg(app, url, method, querystring.parse(nowaData));
    });
  }

  switch(request.method) {
    case 'GET':
      dealArg(app, url, 'get');
      break;
    case 'POST':
      dealTask('post');
      break;
    case 'PUT':
      dealTask('put');
      break;
    case 'DELETE':
      dealTask('delete');
      break;
    default:
      dealArg(app, url, 'get');
  }
}

exports.response = response;
