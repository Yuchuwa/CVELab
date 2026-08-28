
var support = ['.html', '.css', '.js', '.jpg', '.png', '.gif', '.jpeg', '.woff', '.woff2', '.ttf', '.svg'];

function contentType(url) {
  var res = {};
  switch(support.indexOf(url.match(/.[^.]+$/)[0])) {
    case 0:
      res['Content-Type'] = 'text/html;charset=utf-8'
      break;
    case 1:
      res['Content-Type'] = 'text/css'
      break;
    case 2:
      res['Content-Type'] = 'application/x-javascript'
      break;
    case 3:
    case 4:
    case 5:
    case 6:
      res['Content-Type'] = 'image/jpeg'
      break;
    case 7:
    case 8:
      res['Access-Control-Allow-Origin'] = '*';
      res['Content-Type'] = 'application/x-font-woff';
      res['Accept-Ranges'] = 'bytes'
      break;
    case 9:
      res['Content-Type'] = 'application/x-font-ttf'
      break;
    case 10:
      res['Content-Type'] = 'text/xml'
      break;
    default:
      res['Content-Type'] = 'text/html;charset:utf-8'
      break;
  }
  return res;
}

exports.contentType = contentType;
