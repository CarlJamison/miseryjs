const fs = require('fs');

module.exports = {
    handlers: [
        {   
            returnType: 1,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;

                //TODO store agent files on server
                
                return true;
            }
        }
    ],
    listeners:[
        {
            name: 'server-upload',
            handle: (scope, msg) => {
                if(!fs.existsSync("file_storage")){
                    fs.mkdirSync("file_storage");
                }

                var buffer = Buffer.from(msg.args[1], 'base64');

                fs.writeFile("file_storage/" + msg.args[0], buffer, (err) => {
                    scope.socket.emit('echo', err ? err.toString() : 'File uploaded');
                });
            }
        }
    ]

}