import {createServer} from 'node:http';
import {Readable} from 'node:stream';
/** Minimal Node HTTP bridge for the examples and real network tests. */
export async function listen(handler,port=0){
  const server=createServer(async(req,res)=>{
    try{
      const method=req.method??'GET';
      const headers=new Headers();for(let i=0;i<req.rawHeaders.length;i+=2)headers.append(req.rawHeaders[i],req.rawHeaders[i+1]);
      const input=new Request(`http://127.0.0.1:${server.address().port}${req.url}`,{method,headers,...['GET','HEAD'].includes(method)?{}:{body:Readable.toWeb(req),duplex:'half'}});
      const response=await handler(input);
      res.statusCode=response.status;for(const [k,v] of response.headers)if(k!=='set-cookie')res.setHeader(k,v);
      const cookies=response.headers.getSetCookie();if(cookies.length)res.setHeader('Set-Cookie',cookies);
      if(!response.body){res.end();return;}Readable.fromWeb(response.body).pipe(res);
    }catch{if(!res.headersSent)res.writeHead(500);res.end();}
  });
  await new Promise((ok,fail)=>{server.once('error',fail);server.listen(port,'127.0.0.1',ok);});
  return {url:`http://127.0.0.1:${server.address().port}`,close:()=>new Promise((ok,fail)=>{server.close(e=>e?fail(e):ok());server.closeAllConnections?.();})};
}
