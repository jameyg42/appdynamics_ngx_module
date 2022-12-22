const http = require('http');
const server = http.createServer((request, response) => {
   response.write(JSON.stringify(request.headers));
   response.end();
}).listen(8083);
